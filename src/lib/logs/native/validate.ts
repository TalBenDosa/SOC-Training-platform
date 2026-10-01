import type { NativeLog, SourceSchema } from "./types";
import { leafPaths, getAll } from "./paths";

export interface Violation { path: string; problem: "unknown_field" | "missing_required" | "unknown_kind" | "foreign_namespace" }

/**
 * Prefixes that belong to a SIEM normalisation layer or another vendor and must
 * never appear in a native record (the "no schema mixing" rule).
 */
const FOREIGN_PREFIXES = [
  "data.", "rule.", "agent.", "decoder.", "manager.",            // Wazuh envelope
  "aws.cloudtrail.", "aws.guardduty.", "azure.signinlogs.", "okta.", "crowdstrike.", "s1.", "sophos.",
  "mde.", "zscaler.", "pan.", "cisco.", "checkpoint.", "fortinet.", "gws.", "winlog.", "o365.",
  "event.module", "event.dataset", "ecs.", "@metadata",
];

/** Validate one native log against its source schema. Empty array = clean. */
export function validateNative(log: NativeLog, schema: SourceSchema): Violation[] {
  const kind = schema.kinds[log.kind];
  if (!kind) return [{ path: log.kind, problem: "unknown_kind" }];
  const allowed = new Set([...kind.required, ...kind.optional]);
  const open = kind.openPrefixes ?? [];
  const out: Violation[] = [];
  for (const p of leafPaths(log.record)) {
    if (allowed.has(p)) continue;
    // A parent path declared as a whole object/array (e.g. "requestParameters") covers its leaves.
    if ([...allowed].some(a => p.startsWith(`${a}.`) || p.startsWith(`${a}[]`))) continue;
    if (open.some(o => p === o || p.startsWith(`${o}.`) || p.startsWith(`${o}[]`))) continue;
    out.push({ path: p, problem: FOREIGN_PREFIXES.some(f => p.startsWith(f)) && !allowedByVendor(p, schema) ? "foreign_namespace" : "unknown_field" });
  }
  for (const r of kind.required) {
    const vals = getAll(log.record, r);
    if (vals.length === 0 || vals.every(v => v === undefined)) out.push({ path: r, problem: "missing_required" });
  }
  return out;
}

/** Some vendors' own native keys start with a string in FOREIGN_PREFIXES (e.g. S1 "agent.uuid"). */
function allowedByVendor(path: string, schema: SourceSchema): boolean {
  for (const k of Object.values(schema.kinds)) if (k.required.includes(path) || k.optional.includes(path)) return true;
  return false;
}
