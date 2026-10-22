/**
 * Native log registry — one module per data source (docs/log-schemas cards).
 *
 *   nativize(ev, companyId, stack?)  → the event in its source's native format
 *   useCasesFor(sourceId?)            → the detection use cases written on those logs
 *
 * CyberArk PAM renders as the Vault's CEF audit line; Windows Security / Active
 * Directory events render as native EVTX Security-log records.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeLog, NativeSource, SourceId, UseCase } from "./types";
import { makeCtx } from "./ctx";
import { edrFacts, threadOf, withThread } from "./sources/edr-normalize";
import { procPid, threadEndpointStory, hostKey } from "./sources/_proc-identity";
import { threadIdentityContext } from "./sources/_identity-common";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
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
import { source as cyberark } from "./sources/cyberark";
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
import { source as windows_security } from "./sources/windows_security";
import { source as zscaler_zia } from "./sources/zscaler_zia";
import { source as zscaler_zpa } from "./sources/zscaler_zpa";
import { source as workday } from "./sources/workday";

export const NATIVE_SOURCES: Partial<Record<SourceId, NativeSource>> = {
  anyconnect, aws_cloudtrail, aws_guardduty, aws_vpcflow, azure_activity, checkpoint, cisco_asa, cisco_ftd,
  cloudflare_access, crowdstrike, defender_o365, entra, fortigate, fortigate_sslvpn, gcp_audit, globalprotect,
  google_workspace, infoblox, k8s_audit, linux_auditd, m365, mde, okta, paloalto, proofpoint, sentinelone,
  servicenow, sophos, sysmon, windows_dns, zscaler_zia, zscaler_zpa,
  cyberark, windows_security, workday,
};

export function stackFor(companyId: string, override?: Stack): Stack {
  return coherentStack({ ...(COMPANY_STACKS[companyId] ?? {}), ...(override ?? {}) });
}

/**
 * The event in its source's native format under the company's stack, or null when
 * no module covers its category yet / the chosen product has no such record.
 * Never throws — a converter bug must not take the feed down.
 */
/** A named organization's identity for the renderers (a team exercise run as the instructor's org). */
export interface NativeIdentity { domain: string; netbios: string }

export function nativize(ev: TelemetryEvent, companyId: string, stack?: Stack, identity?: NativeIdentity): NativeLog | null {
  const id = sourceFor(ev, stackFor(companyId, stack));
  const mod = id ? NATIVE_SOURCES[id] : undefined;
  if (!mod) return null;
  try { return mod.fromTelemetry(ev, makeCtx(companyId, identity ?? {})); } catch { return null; }
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
export function nativeView(ev: TelemetryEvent, companyId: string, stack?: Stack, identity?: NativeIdentity): { log: NativeLog; product: string } | null {
  // A stacked event renders through its authored source/vendor (the converter path the corpus gate tests).
  const log = nativize(authoredOf(ev), companyId, stack, identity);
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

/**
 * A story written for another company, run on this company's products: an event that stays
 * on the product it was written for follows the company rule (storyHonoursLocks); an event
 * shown as a DIFFERENT product (an Okta sign-in in an Entra shop) must be one that product
 * really produces (fitsStack) — never another product's record under this one's label.
 */
export function storyFitsOrg(events: TelemetryEvent[], companyId: string, stack?: Stack): boolean {
  const eff = stackFor(companyId, stack);
  return events.every(e => {
    const base = authoredOf(e);
    const id = sourceFor(base, eff);
    if (lockedOut(base, id)) return false;
    if (!id || id === sourceFor(base, {})) return true;
    return fitsStack(e, companyId, stack);
  });
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
  if (!PID_SOURCES.has(ev.source)) return ev;
  let pids: { pid?: number; parentPid?: number };
  try { pids = canonicalPids(ev, companyId); } catch { return ev; }
  const { pid, parentPid } = pids;
  // An event whose process lives only in its raw block (an MDE network row's InitiatingProcessId, a Sysmon
  // ProcessId): the text quoting that pid still follows the record.
  if (!ev.process) {
    const f = edrFacts(authoredOf(ev));
    let d = ev.description;
    for (const [from, to] of [[f.proc.pid, pid], [f.parent.pid, parentPid]] as const) {
      if (d && from !== undefined && to !== undefined && from !== to) d = d.replace(new RegExp(`(\\bPID[ :=#]*|\\bpid[ :=#]*|ProcessId[ :=]*)${from}\\b`, "g"), `$1${to}`);
    }
    return d === ev.description ? ev : { ...ev, description: d };
  }
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

// ── Standalone scenario: one story, one set of identities ───────────────────

const PRIVATE_V4 = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}(\.\d{1,3})?$/;
const HOSTED = new Set(["edr", "av", "sysmon", "linux_audit"]);
const sv = (v: unknown) => (v === undefined || v === null || v === "" || v === "-" ? undefined : String(v));

/** The organization a scenario's events belong to: a known company by its mail domain, else that domain itself. */
function storyOrg(events: TelemetryEvent[]): { companyId: string; identity?: NativeIdentity } {
  const votes = new Map<string, number>();
  for (const e of events) {
    const d = (e.user_email ?? e.user?.email ?? "").split("@")[1]?.toLowerCase();
    if (d) votes.set(d, (votes.get(d) ?? 0) + 1);
  }
  const top = [...votes.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  if (!top) return { companyId: "nexacorp" };
  const known = Object.entries(COMPANY_ASSETS).find(([, a]) => a.domain.toLowerCase() === top);
  if (known) return { companyId: known[0] };
  // A scenario org with no company profile (Northwind Logistics): its own domain and realm, never NexaCorp's.
  return { companyId: "nexacorp", identity: { domain: top, netbios: top.split(".")[0].replace(/[^a-z0-9]/gi, "").toUpperCase().slice(0, 15) } };
}

/** Every address the story gives a host for itself (an EDR row's own IP, a firewall / proxy / DNS row's source). */
function storyHostIps(events: TelemetryEvent[]): Map<string, string> {
  const out = new Map<string, string>();
  const note = (host: unknown, ip: unknown) => {
    const h = sv(host), a = sv(ip);
    if (h && a && PRIVATE_V4.test(a) && !out.has(hostKey(h))) out.set(hostKey(h), a);
  };
  // 1. The host's own address as its sensor states it.
  for (const e of events) {
    const r = (e.raw ?? {}) as Record<string, unknown>;
    if (HOSTED.has(e.source)) note(e.hostname ?? r["host.name"], r["host.ip"] ?? r["crowdstrike.LocalAddressIP4"] ?? r["LocalIP"] ?? r["s1.agent.localIp"]);
  }
  // 2. The source of the host's own outbound network rows.
  for (const e of events) if (["firewall", "proxy", "dns"].includes(e.source)) note(e.hostname, e.src_ip);
  // 3. Host telemetry that carries the host's address as its source (not a logon's remote end).
  for (const e of events) if (HOSTED.has(e.source) && e.event_type !== "net_connection") note(e.hostname, e.src_ip);
  for (const e of events) { const r = (e.raw ?? {}) as Record<string, unknown>; note(e.hostname ?? r["host.name"], r["host.ip"]); }
  return out;
}

/** (sAMAccountName -> SID) as the story authors it, in every vocabulary the scenarios use. */
const SID_KEYS: [string, string][] = [
  ["winlog.event_data.TargetUserName", "winlog.event_data.TargetUserSid"], ["winlog.event_data.SubjectUserName", "winlog.event_data.SubjectUserSid"],
  ["winlog.event_data.MemberName", "winlog.event_data.MemberSid"], ["winlog.event_data.TargetUserName", "winlog.event_data.TargetSid"],
  ["TargetUserName", "TargetUserSid"], ["SubjectUserName", "SubjectUserSid"], ["AccountName", "AccountSid"],
  ["InitiatingProcessAccountName", "InitiatingProcessAccountSid"], ["crowdstrike.UserName", "crowdstrike.UserSid"], ["user.name", "user.id"],
];
function storySids(events: TelemetryEvent[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const e of events) for (const [uk, sk] of SID_KEYS) {
    const name = sv(e.raw?.[uk]);
    const sid = sv(e.raw?.[sk]);
    if (!name || !sid || !/^S-1-5-21-\d+-\d+-\d+-\d+$/.test(sid)) continue;
    const sam = name.replace(/^CN=([^,]+),.*$/i, "$1").split("\\").pop()!.split("@")[0].toLowerCase();
    if (!sam || sam.endsWith("$") || out.has(sam)) continue;
    out.set(sam, sid);
  }
  return out;
}

/**
 * An assumed-role session starts at the AssumeRole call that created it: the CloudTrail records the
 * session then makes carry that time as sessionContext.attributes.creationDate (never an hour earlier).
 */
const CREATION = "aws.cloudtrail.userIdentity.sessionContext.attributes.creationDate";
function threadRoleSessions(events: TelemetryEvent[]): TelemetryEvent[] {
  const starts: { t: number; role: string; session: string }[] = [];
  for (const e of events) {
    const r = (e.raw ?? {}) as Record<string, unknown>;
    if ((sv(r["aws.cloudtrail.eventName"]) ?? e.cloud?.api_call) !== "AssumeRole" || sv(r["aws.cloudtrail.errorCode"])) continue;
    let p: Record<string, unknown> = {};
    try { p = JSON.parse(String(r["aws.cloudtrail.request_parameters"] ?? r["aws.cloudtrail.requestParameters"] ?? "{}")); } catch { /* flattened keys below */ }
    const roleArn = sv(p.roleArn ?? r["aws.cloudtrail.requestParameters.roleArn"]);
    const session = sv(p.roleSessionName ?? r["aws.cloudtrail.requestParameters.roleSessionName"]);
    if (roleArn && session) starts.push({ t: Date.parse(e.ts), role: roleArn.split("/").pop()!.toLowerCase(), session: session.toLowerCase() });
  }
  if (!starts.length) return events;
  return events.map(e => {
    const r = (e.raw ?? {}) as Record<string, unknown>;
    const m = /:assumed-role\/([^/]+)\/(.+)$/.exec(sv(r["aws.cloudtrail.userIdentity.arn"]) ?? "");
    if (!m) return e;
    const t = Date.parse(e.ts);
    const start = starts.filter(s => s.role === m[1].toLowerCase() && s.session === m[2].toLowerCase() && s.t <= t && t - s.t <= 12 * 3_600_000).pop();
    if (!start) return e;
    const authored = sv(r[CREATION]);
    if (authored && Date.parse(authored) >= start.t && Date.parse(authored) <= t) return e;
    return { ...e, raw: { ...r, [CREATION]: new Date(start.t).toISOString().replace(/\.\d{3}Z$/, "Z") } };
  });
}

/**
 * The renderer for one standalone scenario. A scenario page shows each row through this (instead of
 * nativeViewAuthored row by row) so the story's records agree with each other and with its EDR console:
 *   - the authored OS pid / parent pid of a process is what every EDR / Sysmon record prints;
 *   - a host has ONE IP in every product: the address any row of the story gives it, else one derived per host;
 *   - an account has ONE SID in every product: the SID the story authors for it, else one per company + user;
 *   - the endpoint story pass (canonical image paths / hashes, a parent's command line, the writer of an
 *     unattributed file, the logon session of each day, a process's start time) runs over the whole story;
 *   - the records name the scenario's own organization (its domain and realm), never another company's.
 * Each event renders in the format of the vendor it was authored for, as nativeViewAuthored does.
 */
export function nativeStoryRenderer(events: TelemetryEvent[], companyId?: string): (ev: TelemetryEvent) => { log: NativeLog; product: string } | null {
  const org = companyId ? { companyId } : storyOrg(events);
  const ctx = { ...makeCtx(org.companyId, org.identity ?? {}), authoredPids: true, hostIps: storyHostIps(events), userSids: storySids(events) };
  // The identity pass (one place per client IP, one session per login flow, a UAL token issued at the
  // sign-in that opened it) and the endpoint pass, exactly as the live feed runs them on a story.
  const original = new Map(events.map(e => [e.id, e]));
  const prepared = threadEndpointStory(threadIdentityContext(threadRoleSessions(events)));
  const byId = new Map<string, { raw: Record<string, unknown>; geo?: TelemetryEvent["geo"]; thread?: ReturnType<typeof threadOf> }>();
  for (const p of prepared) {
    const o = original.get(p.id);
    if (!o) continue;
    // Only what the passes changed travels to the row (the caller's own row stays the base).
    const raw: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(p.raw ?? {})) if ((o.raw ?? {})[k] !== v) raw[k] = v;
    byId.set(p.id, { raw, geo: p.geo !== o.geo ? p.geo : undefined, thread: threadOf(p) });
  }
  return (ev: TelemetryEvent) => {
    const id = sourceFor(ev, {});
    const mod = id ? NATIVE_SOURCES[id] : undefined;
    if (!mod) return null;
    const story = byId.get(ev.id);
    let input = ev;
    if (story) {
      if (Object.keys(story.raw).length || story.geo) input = { ...input, raw: { ...(input.raw ?? {}), ...story.raw }, ...(story.geo ? { geo: story.geo } : {}) };
      if (story.thread && !threadOf(ev)) input = withThread(input, story.thread);
    }
    try {
      const log = mod.fromTelemetry(input, ctx);
      return log ? { log, product: mod.schema.product } : null;
    } catch { return null; }
  };
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
