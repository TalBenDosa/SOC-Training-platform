/**
 * Native log registry — one module per data source (docs/log-schemas cards).
 *
 *   nativize(ev, companyId, stack?)  → the event in its source's native format
 *   useCasesFor(sourceId?)            → the detection use cases written on those logs
 *
 * Windows Security and CyberArk have no native module yet: their events keep the
 * legacy rendering (nativize returns null for them).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeLog, NativeSource, SourceId, UseCase } from "./types";
import { makeCtx } from "./ctx";
import { edrFacts } from "./sources/edr-normalize";
import { procPid } from "./sources/_proc-identity";
import { COMPANY_STACKS, sourceFor, categoryOf, rewriteProductText, PRODUCT_LABEL, coherentStack, PRODUCT_LOCKS, M365_CLIENT_TEXT, M365_CLIENT_RECORD, MS_LOGIN_RECORD, STACK_CHOICES, type Stack, type StackCategory } from "./stack";

import { source as anyconnect } from "./sources/anyconnect";
import { source as aws_cloudtrail } from "./sources/aws_cloudtrail";
import { source as aws_guardduty } from "./sources/aws_guardduty";
import { source as aws_vpcflow } from "./sources/aws_vpcflow";
import { source as azure_activity } from "./sources/azure_activity";
import { source as checkpoint } from "./sources/checkpoint";
import { source as cisco_asa } from "./sources/cisco_asa";
import { source as cisco_ftd } from "./sources/cisco_ftd";
import { source as cloudflare_access } from "./sources/cloudflare_access";
import { source as crowdstrike } from "./sources/crowdstrike";
import { source as defender_o365 } from "./sources/defender_o365";
import { source as entra } from "./sources/entra";
import { source as fortigate } from "./sources/fortigate";
import { source as fortigate_sslvpn } from "./sources/fortigate_sslvpn";
import { source as gcp_audit } from "./sources/gcp_audit";
import { source as globalprotect } from "./sources/globalprotect";
import { source as google_workspace } from "./sources/google_workspace";
import { source as infoblox } from "./sources/infoblox";
import { source as k8s_audit } from "./sources/k8s_audit";
import { source as linux_auditd } from "./sources/linux_auditd";
import { source as m365 } from "./sources/m365";
import { source as mde } from "./sources/mde";
import { source as okta } from "./sources/okta";
import { source as paloalto } from "./sources/paloalto";
import { source as proofpoint } from "./sources/proofpoint";
import { source as sentinelone } from "./sources/sentinelone";
import { source as servicenow } from "./sources/servicenow";
import { source as sophos } from "./sources/sophos";
import { source as sysmon } from "./sources/sysmon";
import { source as windows_dns } from "./sources/windows_dns";
import { source as zscaler_zia } from "./sources/zscaler_zia";
import { source as zscaler_zpa } from "./sources/zscaler_zpa";

export const NATIVE_SOURCES: Partial<Record<SourceId, NativeSource>> = {
  anyconnect, aws_cloudtrail, aws_guardduty, aws_vpcflow, azure_activity, checkpoint, cisco_asa, cisco_ftd,
  cloudflare_access, crowdstrike, defender_o365, entra, fortigate, fortigate_sslvpn, gcp_audit, globalprotect,
  google_workspace, infoblox, k8s_audit, linux_auditd, m365, mde, okta, paloalto, proofpoint, sentinelone,
  servicenow, sophos, sysmon, windows_dns, zscaler_zia, zscaler_zpa,
};

export function stackFor(companyId: string, override?: Stack): Stack {
  return coherentStack({ ...(COMPANY_STACKS[companyId] ?? {}), ...(override ?? {}) });
}

/**
 * The event in its source's native format under the company's stack, or null when
 * no module covers its category yet / the chosen product has no such record.
 * Never throws — a converter bug must not take the feed down.
 */
export function nativize(ev: TelemetryEvent, companyId: string, stack?: Stack): NativeLog | null {
  const id = sourceFor(ev, stackFor(companyId, stack));
  const mod = id ? NATIVE_SOURCES[id] : undefined;
  if (!mod) return null;
  try { return mod.fromTelemetry(ev, makeCtx(companyId)); } catch { return null; }
}

/** Use cases for one source, or every source. */
export function useCasesFor(sourceId?: SourceId): UseCase[] {
  if (sourceId) return NATIVE_SOURCES[sourceId]?.useCases ?? [];
  return Object.values(NATIVE_SOURCES).flatMap(s => s?.useCases ?? []);
}

export type { NativeLog, NativeSource, SourceId, UseCase } from "./types";
export type { Stack } from "./stack";
export { STACK_CHOICES, PRODUCT_LABEL, sanitizeStack, COMPANY_STACKS } from "./stack";

/** nativize + the product display name, for the feed UI (NativeLogContext). */
export function nativeView(ev: TelemetryEvent, companyId: string, stack?: Stack): { log: NativeLog; product: string } | null {
  // A stacked event renders through its authored source/vendor (the converter path the corpus gate tests).
  const log = nativize(authoredOf(ev), companyId, stack);
  if (!log) return null;
  return { log, product: NATIVE_SOURCES[log.sourceId]?.schema.product ?? log.sourceId };
}

// ── Stack application (vendor choice) ────────────────────────────────────────

/**
 * An event shown under a chosen stack keeps only its authored source + vendor (never a
 * copy of the authored event: in a team session that would ship answer fields to players).
 */
type StackedEvent = TelemetryEvent & { _authored_source?: string; _authored_vendor?: string };
/** The event as it was authored (source / vendor restored), everything else as shown. */
export function authoredOf(ev: TelemetryEvent): TelemetryEvent {
  const e = ev as StackedEvent;
  if (e._authored_source === undefined && e._authored_vendor === undefined) return ev;
  const { _authored_source, _authored_vendor, ...rest } = e;
  return { ...rest, source: (_authored_source ?? ev.source) as TelemetryEvent["source"], vendor: _authored_vendor ?? ev.vendor };
}

/** Endpoint / network telemetry: its records name the client software that really ran. */
const CLIENT_SIDE = new Set<string>(["edr", "host_telemetry", "onprem_ad", "dns", "firewall", "proxy"]);

/**
 * Can this event exist in a shop running `stack`? The chosen product must have a real
 * record for it (Sophos has no DNS stream, Google has no inbox rules, ZPA logs no
 * password failures …); an event citing another product's own artifacts (PRODUCT_LOCKS)
 * can't be shown as the chosen one; and a Google Workspace shop's endpoints don't run
 * Outlook / Teams / OneDrive or sign in to Microsoft (unless Entra is its IdP).
 */
/** The event cites artifacts of the product it was written for, and the stack shows it as another. */
function lockedOut(base: TelemetryEvent, id: string | null): boolean {
  if (!id || !NATIVE_SOURCES[id as keyof typeof NATIVE_SOURCES]) return false;
  const authored = sourceFor(base, {});
  return !!authored && authored !== id && !!PRODUCT_LOCKS[authored]?.test(base.description ?? "");
}

/**
 * The lock rule alone: no event of the story is a vendor-specific one shown as another
 * vendor. Used for the company's own products, where a record the product lacks just
 * stays in the legacy view (the full fitsStack rule is for a chosen stack).
 */
export function storyHonoursLocks(events: TelemetryEvent[], companyId: string, stack?: Stack): boolean {
  const eff = stackFor(companyId, stack);
  return events.every(e => { const base = authoredOf(e); return !lockedOut(base, sourceFor(base, eff)); });
}

export function fitsStack(ev: TelemetryEvent, companyId: string, stack?: Stack): boolean {
  const base = authoredOf(ev);
  const eff = stackFor(companyId, stack);
  const cat = categoryOf(base);
  const id = sourceFor(base, eff);
  if (lockedOut(base, id)) return false;
  const log = id && NATIVE_SOURCES[id] ? nativize(base, companyId, stack) : undefined;
  if (log === null) return false;
  if (eff.collab === "google_workspace" && cat && CLIENT_SIDE.has(cat)) {
    if (M365_CLIENT_TEXT.test(base.description ?? "")) return false;
    const rec = log ? JSON.stringify(log.record) : "";
    if (M365_CLIENT_RECORD.test(rec)) return false;
    if (eff.idp !== "entra" && (MS_LOGIN_RECORD.test(rec) || MS_LOGIN_RECORD.test(base.description ?? ""))) return false;
  }
  return true;
}

/** Every event of a story can be rendered under the stack (so the attack plays out whole). */
export function storyFitsStack(events: TelemetryEvent[], companyId: string, stack?: Stack): boolean {
  return events.every(e => fitsStack(e, companyId, stack));
}

/**
 * The event as the chosen stack would show it: vendor = the chosen product, product
 * names in the description switched, the collab / IdP source badge matching the
 * product. The authored source/vendor ride along so native rendering uses
 * exactly the converter path the corpus gate tests.
 */
/**
 * The event as the session shows it: labelled for its products (applyStackLabels) and with
 * the OS pids every native EDR record prints for its process and parent (canonicalPids) — so
 * the EDR console's process tree, the panel's fields and a PID quoted in the text all show the
 * number the record shows.
 */
export function applyStack(ev: TelemetryEvent, companyId: string, stack?: Stack): TelemetryEvent {
  return withCanonicalPids(applyStackLabels(ev, companyId, stack), companyId);
}

const PID_SOURCES = new Set(["edr", "sysmon", "av", "windows_security", "linux_audit"]);
function withCanonicalPids(ev: TelemetryEvent, companyId: string): TelemetryEvent {
  if (!ev.process || !PID_SOURCES.has(ev.source)) return ev;
  let pids: { pid?: number; parentPid?: number };
  try { pids = canonicalPids(ev, companyId); } catch { return ev; }
  const { pid, parentPid } = pids;
  const oldPid = ev.process.pid, oldParent = ev.process.parent_pid;
  if ((pid === undefined || pid === oldPid) && (parentPid === undefined || parentPid === oldParent)) return ev;
  let description = ev.description;
  const swap = (from: number | undefined, to: number | undefined) => {
    if (description && from !== undefined && to !== undefined && from !== to) {
      description = description.replace(new RegExp(`(\\bPID[ :=#]*|\\bpid[ :=#]*|ProcessId[ :=]*)${from}\\b`, "g"), `$1${to}`);
    }
  };
  swap(oldPid, pid); swap(oldParent, parentPid);
  return {
    ...ev,
    description,
    process: { ...ev.process, ...(pid !== undefined ? { pid } : {}), ...(parentPid !== undefined ? { parent_pid: parentPid } : {}) },
  };
}

function applyStackLabels(ev: TelemetryEvent, companyId: string, stack?: Stack): TelemetryEvent {
  const base = authoredOf(ev);
  const cat = categoryOf(base);
  const eff = stackFor(companyId, stack);
  // Products of the categories the session changed, named in any row ("signed in to
  // SharePoint Online" on an IdP event in a Google shop).
  const own = COMPANY_STACKS[companyId] ?? {};
  let description = ev.description;
  for (const c of STACK_CHOICES) {
    const sid = eff[c.category];
    if (sid && c.category !== cat && sid !== own[c.category]) description = rewriteProductText(description, c.category as StackCategory, sid);
  }
  if (!cat || cat === "cloud" || cat === "k8s" || cat === "onprem_ad" || cat === "host_telemetry" || cat === "linux" || cat === "itsm" || cat === "pam") {
    return description === ev.description ? ev : { ...ev, description };
  }
  const id = sourceFor(base, eff);
  if (!id) return description === ev.description ? ev : { ...ev, description };
  const product = PRODUCT_LABEL[id];
  const next: StackedEvent = {
    ...ev,
    _authored_source: base.source,
    _authored_vendor: base.vendor,
    vendor: product ?? ev.vendor,
    description: rewriteProductText(description, cat, id),
  };
  if (cat === "collab") next.source = (id === "google_workspace" ? "gws" : base.source === "gws" ? "o365" : base.source) as TelemetryEvent["source"];
  if (cat === "idp") next.source = (id === "okta" ? "okta" : base.source === "okta" ? "o365" : base.source) as TelemetryEvent["source"];
  // Proofpoint is a mail gateway, not part of Office 365 — the row's source badge says so.
  if (cat === "email_security") next.source = (id === "proofpoint" ? "email_gateway" : base.source === "email_gateway" ? "o365" : base.source) as TelemetryEvent["source"];
  return next;
}

/**
 * A standalone scenario has no company stack: each event renders in the native format
 * of the vendor it was authored for (a CrowdStrike-authored step stays CrowdStrike).
 */
export function nativeViewAuthored(ev: TelemetryEvent): { log: NativeLog; product: string } | null {
  const id = sourceFor(ev, {});
  const mod = id ? NATIVE_SOURCES[id] : undefined;
  if (!mod) return null;
  try {
    const log = mod.fromTelemetry(ev, makeCtx("nexacorp"));
    return log ? { log, product: mod.schema.product } : null;
  } catch { return null; }
}

/**
 * The OS pids the native EDR records print for an event's process and its parent (every EDR
 * module derives them from the process instance — ./sources/_proc-identity — never from the
 * authored pid). For surfaces that print process.pid next to the native record (the feed's field
 * chips, the EDR console's process tree), so all of them show the same number.
 */
export function canonicalPids(ev: TelemetryEvent, companyId: string): { pid?: number; parentPid?: number } {
  const f = edrFacts(authoredOf(ev));
  if (!f.host) return {};
  const ctx = makeCtx(companyId);
  const scope = { host: f.host, os: f.os, timeMs: f.timeMs, user: f.user ?? f.userEmail?.split("@")[0], incident: ev.incident_id };
  return {
    pid: procPid(ctx, scope, f.proc),
    parentPid: f.parent.name || f.parent.path ? procPid(ctx, scope, f.parent) : undefined,
  };
}
