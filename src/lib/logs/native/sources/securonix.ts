/**
 * Securonix SNYPR, violation record as the SNYPR search API returns it (index=violation), native module.
 * No card in docs/log-schemas. The field names are SNYPR's own lower-case violation fields:
 *   - violator (the entity type that violated: "Users", "Activityaccount", "RTActivityAccount" ...),
 *     policyname, riskthreatname, riskscore, tenantname, tenantid, accountname, resourcename,
 *     ipaddress, jobid, datetime (epoch milliseconds, as a string) and generationtime
 *     ("MM/dd/yyyy HH:mm:ss"): the violation data fields of the Securonix integration for Cortex XSOAR
 *     (securonix-list-violation-data output: Violator, Policyname, Riskscore, Tenantname, Accountname,
 *     Resourcename, Datetime, GenerationTime ..., the integration capitalises the API's keys);
 *   - entityid and u_department (the violator's id and its HR department attribute): the violation
 *     fields the ThreatQ Securonix connector searches (entityid, u_firstname, u_lastname, u_department,
 *     violator, accountname ...).
 * Record: flat, string values.
 *
 * Input: `ueba` events of the Securonix vendor, keys under `securonix.`. Other UEBA products are null.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";

const REQUIRED = ["violator", "entityid", "accountname", "policyname", "riskscore", "tenantname", "tenantid", "jobid", "datetime", "generationtime"];
const OPTIONAL = ["riskthreatname", "resourcename", "ipaddress", "u_department"];

const schema: SourceSchema = {
  sourceId: "securonix", category: "ueba", card: "(none: SNYPR violation fields, Securonix integrations for Cortex XSOAR and ThreatQ)", product: "Securonix SNYPR",
  format: "json", vendorMatch: ["securonix"], telemetrySources: ["ueba"],
  kinds: { violation: { required: REQUIRED, optional: OPTIONAL } },
};

export function kindOf(record: Record<string, unknown>): string | null {
  return typeof record.violator === "string" && typeof record.policyname === "string" ? "violation" : null;
}

const str = (v: unknown) => (v === undefined || v === null || v === "" ? undefined : String(v));
const p2 = (n: number) => String(n).padStart(2, "0");
const generation = (ms: number) => { const d = new Date(ms); return `${p2(d.getUTCMonth() + 1)}/${p2(d.getUTCDate())}/${d.getUTCFullYear()} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}`; };

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  if (!/securonix/i.test(ev.vendor ?? "")) return null;
  const raw = (ev.raw ?? {}) as Record<string, unknown>;
  const x = (k: string) => str(raw[`securonix.${k}`]);
  const ms = Date.parse(ev.ts);
  if (!Number.isFinite(ms)) return null;
  const account = x("accountname") ?? x("entityid") ?? (ev.user_email ?? ev.user?.email)?.split("@")[0];
  const policy = x("policyname");
  if (!account || !policy) return null;
  const record: Record<string, string> = {
    violator: x("violator") ?? "Users",
    entityid: x("entityid") ?? account,
    accountname: account,
    ...(x("u_department") ?? ev.user?.department ? { u_department: x("u_department") ?? ev.user!.department! } : {}),
    policyname: policy,
    ...(x("riskthreatname") ? { riskthreatname: x("riskthreatname")! } : {}),
    riskscore: x("riskscore") ?? "0.0",
    ...(x("resourcename") ?? ev.hostname ? { resourcename: x("resourcename") ?? ev.hostname! } : {}),
    ...(x("ipaddress") ?? ev.src_ip ? { ipaddress: x("ipaddress") ?? ev.src_ip! } : {}),
    tenantname: x("tenantname") ?? ctx.org,
    tenantid: x("tenantid") ?? String(ctx.int("securonix:tenantid", 1, 40)),
    jobid: String(ctx.int(`securonix:job:${policy}`, 100, 9000)),
    datetime: String(ms),
    generationtime: generation(ms),
  };
  return { sourceId: "securonix", kind: "violation", format: "json", record, timeMs: ms };
}

const useCases: UseCase[] = [
  {
    id: "securonix.high_risk_violation", title: "Securonix violation with a high risk score", sourceId: "securonix", kinds: ["violation"],
    severity: "high", mitre: ["T1078"],
    description: "A policy violation whose risk score is 80 or above. SNYPR adds the risk of each violation to the entity: read the policy and the threat model, then check the account's recent activity in the original data sources.",
    logic: "SNYPR spotter: index=violation AND riskscore >= 80 | table generationtime accountname policyname riskthreatname riskscore",
    match: { field: "riskscore", op: "gte", value: 80 },
    falsePositives: ["Peer-group outliers after a role change"],
  },
  {
    id: "securonix.privileged_activity_violation", title: "Violation on a privileged-activity policy", sourceId: "securonix", kinds: ["violation"],
    severity: "low", mitre: ["T1078.002"],
    description: "A violation of a policy that baselines privileged or administrative activity. Most are routine admin work; the risk score and the peer comparison tell which ones to open.",
    logic: "SNYPR spotter: index=violation AND policyname CONTAINS \"Privileged\" | table generationtime accountname u_department policyname riskscore",
    match: { field: "policyname", op: "icontains", value: "privileged" },
    falsePositives: ["Patch nights and planned administration"],
  },
  {
    id: "securonix.violation_for_account", title: "Any violation for a watched account", sourceId: "securonix", kinds: ["violation"],
    severity: "low", mitre: [],
    description: "Every violation SNYPR writes for an account, the starting list when an investigation pivots to a person.",
    logic: "SNYPR spotter: index=violation AND accountname = \"<account>\" | sort generationtime",
    match: { field: "violator", op: "exists" },
    falsePositives: ["None: it is a pivot, not a detection"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
