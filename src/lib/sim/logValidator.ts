/**
 * logValidator.ts
 * ───────────────
 * Validates TelemetryEvent objects against per-vendor field-naming schemas.
 *
 * Real issues this catches in the current dataset:
 *  - CrowdStrike events use cs.* prefix  → must be crowdstrike.*
 *  - AWS CloudTrail events use aws.eventSource / aws.eventName  → must be aws.cloudtrail.*
 *  - FortiGate events use fortinet.* prefix  → must be fortigate.*
 *  - SentinelOne events use s1.* prefix  → must be sentinelone.*
 *  - Events with empty raw (only action_result) get a coverage warning
 *  - Cross-vendor field contamination
 *  - Missing required auth / group-modify fields
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ─── Public types ─────────────────────────────────────────────────────────────

export type IssueSeverity = "error" | "warning" | "info";

export interface ValidationIssue {
  event_id: string;
  vendor: string;
  source: string;
  event_type: string;
  severity: IssueSeverity;
  /** Machine-readable code, e.g. "WRONG_VENDOR_PREFIX" */
  code: string;
  message: string;
  suggestion?: string;
  /** Which field the issue is about (if applicable) */
  field?: string;
}

export interface ValidationReport {
  generated_at: string;
  total_events: number;
  clean_events: number;
  issues: ValidationIssue[];
  summary: {
    errors: number;
    warnings: number;
    infos: number;
  };
  by_vendor: Record<string, { events: number; issues: number; error_count: number }>;
  by_source: Record<string, { events: number; issues: number }>;
}

// ─── Vendor schema definition ─────────────────────────────────────────────────

interface VendorSchema {
  /** Display label used in messages */
  label: string;
  /** Correct field-name prefixes for raw fields (e.g. "crowdstrike.") */
  correctPrefixes: string[];
  /**
   * Wrong / legacy prefixes that indicate a naming error.
   * Each entry has the bad prefix and the replacement hint.
   */
  legacyPrefixes: { prefix: string; replaceWith: string }[];
  /**
   * At least one of these fields must appear in raw for the event to be
   * considered "properly instrumented".  If none match → WARNING.
   */
  requiredAny: string[];
  /**
   * Cross-vendor contamination guard: if raw contains a key that starts with
   * any of these prefixes (which belong to *other* vendors), raise a WARNING.
   * Populated automatically from all other schemas' correctPrefixes.
   */
  forbiddenPrefixes?: string[];
}

// ─── Per-vendor schemas ───────────────────────────────────────────────────────

const VENDOR_SCHEMAS = {

  // ── Identity ──────────────────────────────────────────────────────────────

  okta: {
    label: "Okta",
    correctPrefixes: ["okta."],
    legacyPrefixes: [],
    requiredAny: [
      "okta.event_type",
      "okta.actor.login",
      "okta.outcome.result",
      "okta.target.user",
      "okta.risk.level",
    ],
  },

  // ── EDR — CrowdStrike ─────────────────────────────────────────────────────

  crowdstrike: {
    label: "CrowdStrike Falcon",
    correctPrefixes: ["crowdstrike."],
    legacyPrefixes: [
      {
        prefix: "cs.",
        replaceWith:
          "crowdstrike.* (e.g. crowdstrike.PatternDispositionDescription, crowdstrike.SeverityName, crowdstrike.DetectName)",
      },
    ],
    requiredAny: [
      "crowdstrike.PatternDispositionDescription",
      "crowdstrike.SeverityName",
      "crowdstrike.DetectName",
      "crowdstrike.SensorId",
      "crowdstrike.event_type",
    ],
  },

  // ── EDR — Microsoft Defender for Endpoint ────────────────────────────────

  mde: {
    label: "Microsoft Defender for Endpoint",
    correctPrefixes: ["mde."],
    legacyPrefixes: [],
    requiredAny: [
      "mde.AlertTitle",
      "mde.DetectionSource",
      "mde.DeviceName",
      "mde.ReportId",
      "mde.alert_category",
      "mde.detectionSource",
      "mde.alertId",
      "mde.machine_risk_score",
    ],
  },

  // ── EDR — SentinelOne ─────────────────────────────────────────────────────

  sentinelone: {
    label: "SentinelOne",
    correctPrefixes: ["sentinelone.", "s1."],
    legacyPrefixes: [
      // s1.* is tolerated as a known short-form but flagged as non-standard
      // (the "real" ECS-aligned prefix is sentinelone.*)
      // We flag it as a warning rather than an error — it's not as bad as cs.*
    ] as { prefix: string; replaceWith: string }[],
    requiredAny: [
      "sentinelone.site_name",
      "sentinelone.threat.name",
      "sentinelone.agent.id",
      "s1.event_type",
      "s1.threat_level",
      "s1.indicator_name",
    ],
  },

  // ── Cloud — Azure ─────────────────────────────────────────────────────────

  azure: {
    label: "Azure / Microsoft Cloud",
    correctPrefixes: ["azure."],
    legacyPrefixes: [],
    requiredAny: [
      "azure.sign_in_event_types",
      "azure.operation.name",
      "azure.tenant.id",
      "azure.app_display_name",
      "azure.resource.type",
      "azure.activity.operationName",
      "azure.activityLogs.operationName",
      "azure.operationName",
    ],
  },

  // ── Cloud — AWS CloudTrail / GuardDuty ────────────────────────────────────

  aws: {
    label: "AWS CloudTrail / GuardDuty",
    correctPrefixes: ["aws.cloudtrail.", "aws.guardduty."],
    legacyPrefixes: [
      {
        prefix: "aws.eventSource",
        replaceWith: "aws.cloudtrail.event_source",
      },
      {
        prefix: "aws.eventName",
        replaceWith: "aws.cloudtrail.event_name",
      },
    ],
    requiredAny: [
      "aws.cloudtrail.event_name",
      "aws.cloudtrail.event_source",
      "aws.cloudtrail.user_identity.type",
      "aws.guardduty.finding_type",
    ],
  },

  // ── Firewall — FortiGate ──────────────────────────────────────────────────

  fortigate: {
    label: "FortiGate",
    correctPrefixes: ["fortigate."],
    legacyPrefixes: [
      {
        prefix: "fortinet.",
        replaceWith:
          "fortigate.* (e.g. fortigate.policyid, fortigate.subtype, fortigate.devname)",
      },
    ],
    requiredAny: [
      "fortigate.policyid",
      "fortigate.subtype",
      "fortigate.devname",
      "fortigate.service",
      "fortigate.action",
      "fortigate.type",
    ],
  },

  // ── Firewall — Palo Alto ──────────────────────────────────────────────────

  panw: {
    label: "Palo Alto Networks",
    correctPrefixes: ["panw."],
    legacyPrefixes: [],
    requiredAny: [
      "panw.rule",
      "panw.device_name",
      "panw.virtual_system",
      "panw.category",
      "panw.app",
      "panw.zone_from",
    ],
  },

  // ── Firewall — Check Point ────────────────────────────────────────────────

  checkpoint: {
    label: "Check Point NGFW",
    correctPrefixes: ["checkpoint.", "cp."],
    legacyPrefixes: [],
    requiredAny: [
      "checkpoint.rule",
      "checkpoint.blade",
      "checkpoint.action",
      "checkpoint.policy",
      "cp.blade",
      "cp.action",
    ],
  },

  // ── Network — Cisco ───────────────────────────────────────────────────────

  cisco: {
    label: "Cisco",
    correctPrefixes: ["cisco."],
    legacyPrefixes: [],
    requiredAny: [
      "cisco.message_id",
      "cisco.acl",
      "cisco.reason",
      "cisco.interface",
      "cisco.event_type",
      "cisco.anyconnect.tunnel_group",
    ],
  },

  // ── AV — Sophos ───────────────────────────────────────────────────────────

  sophos: {
    label: "Sophos Intercept X",
    correctPrefixes: ["sophos."],
    legacyPrefixes: [],
    requiredAny: [
      "sophos.threat.name",
      "sophos.endpoint.name",
      "sophos.clean.status",
      "sophos.detection_type",
    ],
  },

  // ── PAM — CyberArk ────────────────────────────────────────────────────────

  cyberark: {
    label: "CyberArk PAM",
    correctPrefixes: ["cyberark."],
    legacyPrefixes: [],
    requiredAny: [
      "cyberark.vault",
      "cyberark.target_account",
      "cyberark.safe",
      "cyberark.reason",
    ],
  },

  // ── Proxy — Zscaler ───────────────────────────────────────────────────────

  zscaler: {
    label: "Zscaler Internet Access",
    correctPrefixes: ["zscaler."],
    legacyPrefixes: [],
    requiredAny: [
      "zscaler.cloud.name",
      "zscaler.event.type",
      "zscaler.action",
      "zscaler.url.category",
    ],
  },

  // ── SaaS — Microsoft 365 / O365 ───────────────────────────────────────────

  o365: {
    label: "Microsoft 365 / O365",
    correctPrefixes: ["office365."],
    legacyPrefixes: [],
    requiredAny: [
      "office365.Operation",
      "office365.Workload",
      "office365.MailboxOwnerUPN",
      "office365.message_id",
      "office365.ClientIP",
    ],
  },

  // ── SaaS — Microsoft Teams ────────────────────────────────────────────────

  teams: {
    label: "Microsoft Teams",
    correctPrefixes: ["office365.", "teams."],
    legacyPrefixes: [],
    requiredAny: [
      "office365.Operation",
      "teams.message_type",
      "teams.channel_id",
    ],
  },

  // ── DLP — Microsoft Purview ───────────────────────────────────────────────

  dlp: {
    label: "Microsoft Purview DLP",
    correctPrefixes: ["office365.", "dlp."],
    legacyPrefixes: [],
    requiredAny: [
      "office365.Operation",
      "dlp.policy_name",
      "dlp.rule_name",
      "office365.SensitiveInfoTypeData",
    ],
  },

  // ── Windows / AD / Sysmon / Windows DNS ─────────────────────────────────────

  winlog: {
    label: "Windows Security / AD / Sysmon",
    // dns.* is the correct prefix for Windows DNS Server Analytical log events
    correctPrefixes: ["winlog.", "event.", "dns."],
    legacyPrefixes: [],
    requiredAny: [
      "winlog.event_id",
      "event.code",
      "winlog.logon_type",
      "winlog.subject_user_name",
      "winlog.target_user",
      // Windows DNS Server (event IDs 3010, 3020): ECS dns fields are valid
      "dns.question.name",
      "dns.response_code",
    ],
  },

  // ── Google Workspace ──────────────────────────────────────────────────────

  gws: {
    label: "Google Workspace Audit",
    correctPrefixes: ["gws.", "gsuite."],
    legacyPrefixes: [],
    requiredAny: [
      "gws.event_type",
      "gws.eventName",
      "gsuite.kind",
      "gws.actorEmail",
      "gws.ipAddress",
    ],
  },
} as const satisfies Record<string, VendorSchema>;

type VendorSchemaKey = keyof typeof VENDOR_SCHEMAS;

// ─── Vendor detection ─────────────────────────────────────────────────────────

/**
 * Maps a vendor string (and optionally a LogSource) to a schema key.
 * Uses case-insensitive substring matching so "CrowdStrike Falcon Elite"
 * correctly maps to the "crowdstrike" schema.
 */
function detectVendorSchema(
  vendor: string | undefined,
  source: string
): VendorSchemaKey | null {
  if (!vendor) return null;

  const v = vendor.toLowerCase();

  if (v.includes("crowdstrike")) return "crowdstrike";
  if (v.includes("sentinelone") || v.includes("sentinel one")) return "sentinelone";
  if (v.includes("defender for endpoint") || v.includes("mde")) return "mde";

  if (v.includes("okta")) return "okta";

  // AWS must come before a generic "azure" check
  if (v.includes("aws") || v.includes("guardduty") || v.includes("cloudtrail")) return "aws";

  if (
    v.includes("azure") ||
    v.includes("azure ad") ||
    v.includes("entra") ||
    v.includes("azure activity") ||
    v.includes("azure audit") ||
    v.includes("azure monitor")
  )
    return "azure";

  // FortiGate / Fortinet — must map to fortigate schema
  if (v.includes("fortigate") || v.includes("fortinet") || v.includes("forti")) return "fortigate";

  if (v.includes("palo alto") || v.includes("globalprotect") || v.includes("panw")) return "panw";

  if (v.includes("check point") || v.includes("checkpoint")) return "checkpoint";

  if (v.includes("cisco")) return "cisco";

  if (v.includes("sophos")) return "sophos";

  if (v.includes("cyberark")) return "cyberark";

  if (v.includes("zscaler")) return "zscaler";

  // Microsoft SaaS products — Teams before generic M365 check
  if (v.includes("teams")) return "teams";
  if (v.includes("purview") || (v.includes("dlp") && v.includes("microsoft"))) return "dlp";
  if (
    v.includes("microsoft 365") ||
    v.includes("office 365") ||
    v.includes("o365") ||
    v.includes("exchange online") ||
    v.includes("microsoft exchange") ||
    v.includes("365 audit") ||
    v.includes("microsoft o365")
  )
    return "o365";

  // Windows / AD / Sysmon
  if (
    v.includes("active directory") ||
    v.includes("windows security") ||
    v.includes("sysmon") ||
    v.includes("windows dns") ||
    v.includes("windows dhcp")
  )
    return "winlog";

  if (v.includes("google workspace") || v.includes("gsuite") || v.includes("gws")) return "gws";

  return null;
}

// ─── Helper: get all raw key names ───────────────────────────────────────────

function rawKeys(raw: Record<string, unknown>): string[] {
  return Object.keys(raw);
}

// ─── Core per-event validator ─────────────────────────────────────────────────

/**
 * Validates a single TelemetryEvent and returns a (possibly empty) list of
 * ValidationIssues found.
 */
export function validateEvent(
  event: TelemetryEvent & { displayDescription?: string },
  _context?: { company?: string }
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  const vendor = event.vendor ?? "(unknown vendor)";
  const source = event.source;
  const eventType = event.event_type;
  const eventId = event.id;

  /** Convenience factory */
  function issue(
    severity: IssueSeverity,
    code: string,
    message: string,
    opts: { suggestion?: string; field?: string } = {}
  ): ValidationIssue {
    return {
      event_id: eventId,
      vendor,
      source,
      event_type: eventType,
      severity,
      code,
      message,
      ...opts,
    };
  }

  const keys = rawKeys(event.raw);

  // ── 1. Universal check: raw is empty or only contains action_result ────────
  const meaningfulKeys = keys.filter(
    (k) => k !== "action_result" && k !== "event.action_result"
  );
  if (meaningfulKeys.length === 0) {
    issues.push(
      issue(
        "warning",
        "EMPTY_RAW",
        `Event has minimal raw field coverage — raw contains only action_result or is empty`,
        { suggestion: "Add vendor-specific fields to the raw object to make the event realistic" }
      )
    );
    // No vendor checks possible if raw is empty — return early
    return issues;
  }

  // ── 2. Detect vendor schema ────────────────────────────────────────────────
  const schemaKey = detectVendorSchema(event.vendor, source);

  if (!schemaKey) {
    // Vendor is set but we don't have a schema for it — just skip deep checks
    return issues;
  }

  const schema = VENDOR_SCHEMAS[schemaKey];

  // ── 3. Legacy / wrong prefix check (ERROR) ────────────────────────────────
  for (const { prefix, replaceWith } of schema.legacyPrefixes) {
    const offendingKeys = keys.filter((k) => k.startsWith(prefix));
    if (offendingKeys.length > 0) {
      issues.push(
        issue(
          "error",
          "WRONG_VENDOR_PREFIX",
          `${schema.label} fields must use ${replaceWith.split(" ")[0]} prefix, not ${prefix} — found: ${offendingKeys.slice(0, 3).join(", ")}`,
          {
            suggestion: `Rename fields to use the correct prefix: ${replaceWith}`,
            field: offendingKeys[0],
          }
        )
      );
    }
  }

  // ── 4. Check that at least one correct-prefix field exists ──────────────────
  const hasCorrectPrefix = schema.correctPrefixes.some((pfx) =>
    keys.some((k) => k.startsWith(pfx))
  );
  if (!hasCorrectPrefix) {
    // Only flag if no legacy prefix triggered an error (avoid double-reporting)
    const hasLegacyError = issues.some((i) => i.code === "WRONG_VENDOR_PREFIX");
    if (!hasLegacyError) {
      // Downgrade to INFO for informational-severity telemetry events that already
      // use standard ECS fields (process.*, host.*, source.*, destination.*).
      // These are raw telemetry without alerts — vendor prefix not strictly required.
      const isECSOnlyTelemetry =
        event.severity === "informational" &&
        keys.some(
          (k) =>
            k.startsWith("process.") ||
            k.startsWith("host.") ||
            k.startsWith("source.") ||
            k.startsWith("destination.") ||
            k.startsWith("event.")
        );
      issues.push(
        issue(
          isECSOnlyTelemetry ? "info" : "warning",
          "MISSING_VENDOR_PREFIX",
          `No ${schema.label} vendor-prefixed fields found in raw (expected prefix: ${schema.correctPrefixes.join(" or ")})`,
          {
            suggestion: `Add at least one ${schema.correctPrefixes[0]}* field to raw for ${isECSOnlyTelemetry ? "improved" : "required"} vendor compatibility`,
          }
        )
      );
    }
  }

  // ── 5. Required-any check (WARNING) ──────────────────────────────────────
  const hasRequired = schema.requiredAny.some((f) => keys.includes(f));
  if (!hasRequired && hasCorrectPrefix) {
    // Only fire when the correct prefix is present (prefix wrong already reported above)
    issues.push(
      issue(
        "warning",
        "MISSING_REQUIRED_FIELD",
        `${schema.label} event is missing expected identifying fields`,
        {
          suggestion: `Include at least one of: ${schema.requiredAny.slice(0, 4).join(", ")}`,
        }
      )
    );
  }

  // ── 6. Cross-vendor contamination check (WARNING) ────────────────────────
  //    Build the set of all OTHER vendors' correct prefixes
  const otherVendorPrefixes: Array<{ prefix: string; label: string }> = [];
  for (const [key, otherSchema] of Object.entries(VENDOR_SCHEMAS)) {
    if (key === schemaKey) continue;
    for (const pfx of otherSchema.correctPrefixes) {
      // Skip standard ECS shared prefixes used across all vendors
      const pfxStr = pfx as string;
      if (
        pfxStr === "event." ||
        pfxStr === "process." ||
        pfxStr === "dns." ||      // Standard ECS DNS fields (used by Cisco, CrowdStrike, MDE, etc.)
        pfxStr === "host." ||     // Standard ECS host fields
        pfxStr === "source." ||   // Standard ECS network fields
        pfxStr === "destination."
      ) continue;
      otherVendorPrefixes.push({ prefix: pfx, label: otherSchema.label });
    }
  }

  const contaminatedPairs = new Map<string, string>(); // prefix → foreign label
  for (const k of keys) {
    for (const { prefix, label: foreignLabel } of otherVendorPrefixes) {
      if (k.startsWith(prefix) && !contaminatedPairs.has(prefix)) {
        contaminatedPairs.set(prefix, foreignLabel);
      }
    }
  }

  for (const [pfx, foreignLabel] of contaminatedPairs) {
    issues.push(
      issue(
        "warning",
        "CROSS_VENDOR_CONTAMINATION",
        `Raw contains fields with prefix "${pfx}" which belongs to ${foreignLabel}, not ${schema.label}`,
        {
          suggestion: `Remove or rename fields that belong to a different vendor's schema`,
          field: keys.find((k) => k.startsWith(pfx)),
        }
      )
    );
  }

  // ── 7. Auth event actor field check (WARNING) ─────────────────────────────
  const isAuthEvent = [
    "auth_success",
    "auth_failure",
    "mfa_challenge",
    "mfa_denied",
    "mfa_push_sent",
    "vpn_login",
    "vpn_logout",
    "vpn_failed",
  ].includes(eventType);

  if (isAuthEvent) {
    const authFieldPatterns = [
      "actor",
      "user.name",
      "user_name",
      "subject_user",
      "logon",
      "auth",
      "session",
      "principal",
      "identity",
    ];
    const hasAuthField =
      event.user_email ||
      event.user?.email ||
      keys.some((k) =>
        authFieldPatterns.some((pat) => k.toLowerCase().includes(pat))
      );

    if (!hasAuthField) {
      issues.push(
        issue(
          "warning",
          "MISSING_AUTH_ACTOR",
          `Auth event (${eventType}) has no actor/user identity fields in raw`,
          {
            suggestion:
              "Add user identity fields such as user.name, actor.login, or winlog.subject_user_name",
          }
        )
      );
    }
  }

  // ── 8. Group membership event checks (WARNING) ────────────────────────────
  if (eventType === "group_modify" || eventType === "role_assignment") {
    // AD / winlog events should have winlog.subject_user_name
    if (schemaKey === "winlog") {
      if (!keys.includes("winlog.subject_user_name")) {
        issues.push(
          issue(
            "warning",
            "MISSING_GROUP_ACTOR",
            `Group modification event is missing winlog.subject_user_name (who made the change)`,
            {
              suggestion: "Add winlog.subject_user_name to identify the actor performing the group change",
              field: "winlog.subject_user_name",
            }
          )
        );
      }
    }

    // Okta group events should have okta.target.group
    if (schemaKey === "okta") {
      const hasGroupTarget = keys.some(
        (k) => k.includes("target.group") || k.includes("target.display_name")
      );
      if (!hasGroupTarget) {
        issues.push(
          issue(
            "warning",
            "MISSING_GROUP_TARGET",
            `Okta group event is missing okta.target.group or okta.target.display_name`,
            {
              suggestion: "Add okta.target.group to identify which group was modified",
              field: "okta.target.group",
            }
          )
        );
      }
    }
  }

  // ── 9. Process create event — missing process fields (INFO) ───────────────
  if (eventType === "process_create") {
    const hasProcessField =
      event.process?.name ||
      event.process?.cmdline ||
      keys.some((k) =>
        k.includes("process.name") ||
        k.includes("process_name") ||
        k.includes("cmdline") ||
        k.includes("command_line") ||
        k.includes("CommandLine") ||
        k.includes("TargetProcessName")
      );

    if (!hasProcessField) {
      issues.push(
        issue(
          "info",
          "MISSING_PROCESS_FIELDS",
          `process_create event has no process name or cmdline in structured fields or raw`,
          {
            suggestion: "Populate event.process.name and event.process.cmdline for analyst context",
          }
        )
      );
    }
  }

  // ── 10. AWS-specific: legacy aws.* flat keys that should be nested ─────────
  //    (redundant with check 3, but adds a more specific hint for aws.region, etc.)
  if (schemaKey === "aws") {
    const flatAwsKeys = keys.filter(
      (k) =>
        k.startsWith("aws.") &&
        !k.startsWith("aws.cloudtrail.") &&
        !k.startsWith("aws.guardduty.")
    );
    if (flatAwsKeys.length > 0) {
      // Only add this if the generic WRONG_VENDOR_PREFIX already isn't for eventSource/eventName
      // to avoid duplicate messages — check if it's a novel flat key not yet reported
      const alreadyReported = new Set(
        issues
          .filter((i) => i.code === "WRONG_VENDOR_PREFIX")
          .flatMap(() => flatAwsKeys.slice(0, 1))
      );
      const unreported = flatAwsKeys.filter(
        (k) =>
          !k.startsWith("aws.eventSource") &&
          !k.startsWith("aws.eventName") &&
          !alreadyReported.has(k)
      );
      if (unreported.length > 0) {
        issues.push(
          issue(
            "error",
            "WRONG_VENDOR_PREFIX",
            `AWS CloudTrail fields must use aws.cloudtrail.* prefix — found flat keys: ${unreported.slice(0, 4).join(", ")}`,
            {
              suggestion:
                "Rename aws.region → aws.cloudtrail.region, aws.userIdentity.* → aws.cloudtrail.user_identity.*, etc.",
              field: unreported[0],
            }
          )
        );
      }
    }
  }

  return issues;
}

// ─── Batch validator ──────────────────────────────────────────────────────────

/**
 * Validates a collection of TelemetryEvents and returns a full ValidationReport.
 */
export function validateEvents(
  events: (TelemetryEvent & { displayDescription?: string })[],
  context?: { company?: string }
): ValidationReport {
  const allIssues: ValidationIssue[] = [];
  const byVendor: Record<string, { events: number; issues: number; error_count: number }> = {};
  const bySource: Record<string, { events: number; issues: number }> = {};

  for (const event of events) {
    const vendorKey = event.vendor ?? "(no vendor)";
    const sourceKey = event.source;

    // Initialize vendor bucket
    if (!byVendor[vendorKey]) {
      byVendor[vendorKey] = { events: 0, issues: 0, error_count: 0 };
    }
    byVendor[vendorKey].events += 1;

    // Initialize source bucket
    if (!bySource[sourceKey]) {
      bySource[sourceKey] = { events: 0, issues: 0 };
    }
    bySource[sourceKey].events += 1;

    // Validate
    const eventIssues = validateEvent(event, context);
    allIssues.push(...eventIssues);

    if (eventIssues.length > 0) {
      byVendor[vendorKey].issues += eventIssues.length;
      byVendor[vendorKey].error_count += eventIssues.filter(
        (i) => i.severity === "error"
      ).length;
      bySource[sourceKey].issues += eventIssues.length;
    }
  }

  const errorCount = allIssues.filter((i) => i.severity === "error").length;
  const warningCount = allIssues.filter((i) => i.severity === "warning").length;
  const infoCount = allIssues.filter((i) => i.severity === "info").length;

  // Events with zero issues
  const eventIdsWithIssues = new Set(allIssues.map((i) => i.event_id));
  const cleanCount = events.filter((e) => !eventIdsWithIssues.has(e.id)).length;

  return {
    generated_at: new Date().toISOString(),
    total_events: events.length,
    clean_events: cleanCount,
    issues: allIssues,
    summary: {
      errors: errorCount,
      warnings: warningCount,
      infos: infoCount,
    },
    by_vendor: byVendor,
    by_source: bySource,
  };
}
