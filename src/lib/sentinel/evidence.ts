/**
 * The evidence behind an alert that has no log of its own (a SIEM correlation, a Defender for Cloud
 * alert, a decoy analytic): the rows of the evidence tables that name the alert's entities inside the
 * alert's lookback window. "Events" on such an alert runs this query, never the alert itself
 * (Sdema review I1, 2026-11-08), and the alert's StartTime / EndTime are the first and last of them.
 *
 * Matching is the console's own `has` (whole terms, case-insensitive), so the rows found here are
 * exactly the rows the query returns.
 */
import type { KqlRow, KqlTable } from "@/lib/kql/types";
import { columnType } from "./tables";
import { kstr } from "./rules";

export type NeedleKind = "ip" | "account" | "host" | "azureresource" | "file";
export interface Needle { kind: NeedleKind; value: string }

/** Where each kind of entity is written, per evidence table. */
const WHERE: Record<NeedleKind, Record<string, string[]>> = {
  ip: {
    SigninLogs: ["IPAddress"], AuditLogs: ["InitiatedBy"], OfficeActivity: ["ClientIP"], SecurityEvent: ["IpAddress"], StorageBlobLogs: ["CallerIpAddress"],
    AzureDiagnostics: ["CallerIPAddress", "clientIP_s", "client_ip_s"], ApiManagementGatewayLogs: ["CallerIpAddress"], AzureActivity: ["CallerIpAddress"],
    CommonSecurityLog: ["SourceIP", "DestinationIP"], DeviceNetworkEvents: ["RemoteIP", "LocalIP"], DeviceLogonEvents: ["RemoteIP"], AWSCloudTrail: ["SourceIpAddress"],
    OktaV2_CL: ["SrcIpAddr"], W3CIISLog: ["cIP"], MicrosoftGraphActivityLogs: ["IPAddress"], CloudAppEvents: ["IPAddress"], AGWFirewallLogs: ["ClientIp"], AGWAccessLogs: ["ClientIp"], AWSWAF: ["ClientIp"],
  },
  account: {
    SigninLogs: ["UserPrincipalName"], AuditLogs: ["InitiatedBy", "TargetResources"], OfficeActivity: ["UserId"], SecurityEvent: ["TargetUserName", "SubjectUserName"],
    DeviceProcessEvents: ["AccountName"], DeviceLogonEvents: ["AccountName"], StorageBlobLogs: ["RequesterUpn"], AzureActivity: ["Caller"], OktaV2_CL: ["ActorUsername"],
    CloudAppEvents: ["AccountDisplayName"], EmailEvents: ["RecipientEmailAddress"], MicrosoftGraphActivityLogs: ["UserId"],
  },
  host: {
    SecurityEvent: ["Computer"], Event: ["Computer"], Syslog: ["Computer"], DeviceProcessEvents: ["DeviceName"], DeviceNetworkEvents: ["DeviceName"], DeviceFileEvents: ["DeviceName"],
    DeviceRegistryEvents: ["DeviceName"], DeviceLogonEvents: ["DeviceName"], DeviceEvents: ["DeviceName"], CommonSecurityLog: ["SourceHostName", "DestinationHostName"], W3CIISLog: ["Computer"], NGINX_CL: ["Computer"],
  },
  azureresource: {
    AzureDiagnostics: ["Resource"], StorageBlobLogs: ["AccountName"], ApiManagementGatewayLogs: ["BackendUrl"], AzureActivity: ["ResourceId"],
  },
  file: {
    StorageBlobLogs: ["ObjectKey"], DeviceFileEvents: ["FileName"], OfficeActivity: ["SourceFileName"], EmailAttachmentInfo: ["FileName"],
  },
};

const isTermChar = (c: number) => (c < 128 ? (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) : /[\p{L}\p{N}]/u.test(String.fromCharCode(c)));

/** KQL `has` on one value: the needle as whole terms, case-insensitive. */
export function hasTerm(value: unknown, needle: string): boolean {
  if (value === undefined || value === null || !needle) return false;
  const hay = (typeof value === "object" ? JSON.stringify(value) : String(value)).toLowerCase();
  const n = needle.toLowerCase();
  const edgeL = isTermChar(n.charCodeAt(0)), edgeR = isTermChar(n.charCodeAt(n.length - 1));
  for (let at = hay.indexOf(n); at >= 0; at = hay.indexOf(n, at + 1)) {
    const end = at + n.length;
    if ((!edgeL || at === 0 || !isTermChar(hay.charCodeAt(at - 1))) && (!edgeR || end === hay.length || !isTermChar(hay.charCodeAt(end)))) return true;
  }
  return false;
}

/** The term an entity is searched by: an account by its name before the @, a resource by its own name. */
function term(n: Needle): string {
  if (n.kind === "account") return n.value.split("@")[0].split("\\").pop() ?? n.value;
  if (n.kind === "azureresource") return n.value.replace(/\/+$/, "").split("/").pop() ?? n.value;
  if (n.kind === "host") return n.value.split(".")[0];
  return n.value;
}

const iso = (ms: number) => new Date(ms).toISOString();

/** firstSpecificMs: the first row naming an address, account, host or file (not only the resource). */
export interface Evidence { query: string; rows: KqlRow[]; firstMs?: number; lastMs?: number; firstSpecificMs?: number }

/** The rows naming these entities between fromMs and toMs, and the query that returns them. */
export function evidenceFor(tables: Record<string, KqlTable>, needles: Needle[], fromMs: number, toMs: number): Evidence {
  const parts: string[] = [];
  const rows: KqlRow[] = [];
  const specific: number[] = [];
  const uniq = [...new Map(needles.filter(n => term(n).length >= 3).map(n => [`${n.kind}|${term(n).toLowerCase()}`, n])).values()];
  const tableNames = [...new Set(uniq.flatMap(n => Object.keys(WHERE[n.kind])))];
  for (const t of tableNames) {
    const tbl = tables[t];
    if (!tbl?.rows.length) continue;
    const conds: { col: string; needle: string; dyn: boolean; specific: boolean }[] = [];
    for (const n of uniq) for (const col of WHERE[n.kind][t] ?? []) {
      const type = columnType(t, col);
      if (type) conds.push({ col, needle: term(n), dyn: type === "dynamic", specific: n.kind !== "azureresource" });
    }
    if (!conds.length) continue;
    const hits = tbl.rows.filter(row => {
      const ms = Date.parse(String(row.TimeGenerated));
      return ms >= fromMs && ms <= toMs && conds.some(c => hasTerm(row[c.col], c.needle));
    });
    if (!hits.length) continue;
    rows.push(...hits);
    for (const row of hits) if (conds.some(c => c.specific && hasTerm(row[c.col], c.needle))) specific.push(Date.parse(String(row.TimeGenerated)));
    const where = conds.map(c => `${c.dyn ? `tostring(${c.col})` : c.col} has ${kstr(c.needle)}`).join(" or ");
    parts.push([t, `| where TimeGenerated between (datetime(${iso(fromMs)}) .. datetime(${iso(toMs)}))`, `| where ${where}`].join("\n"));
  }
  const times = rows.map(r => Date.parse(String(r.TimeGenerated))).filter(Number.isFinite);
  const query = !parts.length ? "" : parts.length === 1 ? parts[0] : `union\n${parts.map(p => `(${p.replace(/\n/g, "\n  ")})`).join(",\n")}`;
  return { query, rows, ...(times.length ? { firstMs: Math.min(...times), lastMs: Math.max(...times) } : {}), ...(specific.length ? { firstSpecificMs: Math.min(...specific) } : {}) };
}

/** Entities a feed alert names in its own record: the SecurityAlert Entities list, flat Entities.* keys, Defender for Cloud resource and address. */
export function feedEntities(raw: Record<string, unknown> | undefined): Record<string, unknown>[] | undefined {
  if (!raw) return undefined;
  let list: unknown = raw.Entities;
  if (typeof list === "string") { try { list = JSON.parse(list); } catch { list = undefined; } }
  if (Array.isArray(list) && list.length) return list.filter((e): e is Record<string, unknown> => !!e && typeof e === "object");
  const out: Record<string, unknown>[] = [];
  const s = (k: string) => (typeof raw[k] === "string" && raw[k] ? String(raw[k]) : undefined);
  if (s("Entities.Host.HostName")) out.push({ Type: "host", HostName: s("Entities.Host.HostName") });
  if (s("Entities.Account.Name")) out.push({ Type: "account", Name: s("Entities.Account.Name"), ...(s("Entities.Account.UPNSuffix") ? { UPNSuffix: s("Entities.Account.UPNSuffix") } : {}) });
  if (s("Entities.IP.Address")) out.push({ Type: "ip", Address: s("Entities.IP.Address") });
  if (s("azure.alert.alertType")) {
    if (s("azure.resource.id")) out.push({ Type: "azure-resource", ResourceId: s("azure.resource.id") });
    if (s("source.ip")) out.push({ Type: "ip", Address: s("source.ip") });
  }
  return out.length ? out.map((e, i) => ({ $id: String(i + 2), ...e })) : undefined;
}

/** Search needles from a SecurityAlert Entities list. */
export function needlesOf(entities: Record<string, unknown>[]): Needle[] {
  const out: Needle[] = [];
  for (const e of entities) {
    const t = String(e.Type ?? "").toLowerCase();
    const v = (k: string) => (typeof e[k] === "string" && e[k] ? String(e[k]) : undefined);
    if (t === "ip" && v("Address")) out.push({ kind: "ip", value: v("Address")! });
    else if (t === "account" && v("Name")) out.push({ kind: "account", value: v("UPNSuffix") ? `${v("Name")}@${v("UPNSuffix")}` : v("Name")! });
    else if (t === "host" && v("HostName")) out.push({ kind: "host", value: v("HostName")! });
    else if (t === "azure-resource" && v("ResourceId")) out.push({ kind: "azureresource", value: v("ResourceId")! });
    else if (t === "file" && v("Name")) out.push({ kind: "file", value: v("Name")! });
  }
  return out;
}

/** ExtendedProperties a feed alert states: Sentinel's ExtendedProperties.<Name> and Defender for Cloud's azure.alert.extendedProperties.<Name>. */
export function feedExtendedProperties(raw: Record<string, unknown> | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!raw) return out;
  for (const [k, v] of Object.entries(raw)) {
    const m = /^(?:ExtendedProperties|azure\.alert\.extendedProperties)\.(.+)$/.exec(k);
    if (m && v !== undefined && v !== null && v !== "") out[m[1]] = v;
  }
  return out;
}
