/**
 * Entities of the workspace: what an alert is about. Every Info card fact is read from the released
 * events and their native records: UPN, department and title for accounts, OS, IP and last seen for
 * hosts, geo and ASN for IPs (from the event's `geo`).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KqlRow } from "@/lib/kql/types";
import type { NativeLog } from "@/lib/logs/native/types";
import type { EntityKind, SentinelEntity } from "./types";

const PRIVATE_IP = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/;
export const isPrivateIp = (ip: string) => PRIVATE_IP.test(ip);

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const NON_USERS = /^(system|local service|network service|anonymous logon|unknown|n\/a|-|none|nt authority\\.*|.*\$)$/i;

/** Stable entity key: `${kind}:${lower-cased name}`. */
export const entityId = (kind: EntityKind, name: string) => `${kind}:${name.toLowerCase()}`;

const shortHost = (h: string) => h.split(".")[0];

export function accountOf(ev: TelemetryEvent): string | undefined {
  const email = ev.user_email ?? ev.user?.email;
  if (email && !NON_USERS.test(email)) return email.toLowerCase();
  const pu = ev.process?.user;
  if (pu && !NON_USERS.test(pu)) return pu;
  return undefined;
}

const OS_PATHS: ((r: Record<string, unknown>) => unknown)[] = [
  r => (r.device as { os_version?: unknown } | undefined)?.os_version,
  r => (r.agentRealtimeInfo as { agentOsName?: unknown } | undefined)?.agentOsName,
  r => (r.rawData as { meta_os_name?: unknown } | undefined)?.meta_os_name,
];

function hostOs(ev: TelemetryEvent, log?: NativeLog): string | undefined {
  const rec = log?.record;
  if (rec) {
    for (const read of OS_PATHS) {
      const v = read(rec);
      if (typeof v === "string" && v) return v;
    }
    if (log?.sourceId === "linux_auditd") return "Linux";
    if (log?.sourceId === "windows_security" || log?.sourceId === "sysmon") return "Windows";
  }
  const p = ev.process?.path ?? ev.file?.path;
  if (p) return /^[A-Za-z]:\\/.test(p) ? "Windows" : p.startsWith("/") ? "Linux" : undefined;
  return undefined;
}

/** The department a product states for the user: Zscaler, Purview and UEBA records carry one. */
function departmentOf(ev: TelemetryEvent, log?: NativeLog): string | undefined {
  const zia = (log?.record?.event as { department?: unknown } | undefined)?.department;
  if (typeof zia === "string" && zia) return zia;
  const raw = ev.raw as Record<string, unknown> | undefined;
  const v = raw?.["purview.Department"] ?? raw?.["ueba.peer_group"];
  return typeof v === "string" && v ? v : undefined;
}

/** The address a host's own sensor reports, not a remote end. */
function hostIp(ev: TelemetryEvent, row?: KqlRow): string | undefined {
  const fromRow = row?.DvcIpAddr ?? row?.LocalIP ?? row?.AgentIp;
  if (typeof fromRow === "string" && IPV4.test(fromRow)) return fromRow;
  if (ev.src_ip && isPrivateIp(ev.src_ip) && ["edr", "sysmon", "av", "windows_security", "linux_audit", "firewall", "proxy", "dns"].includes(ev.source)) return ev.src_ip;
  return undefined;
}

export interface EntityRef { id: string; kind: EntityKind }

interface Seen { entity: SentinelEntity; lastSeenMs: number }

/** Accumulates what the released events say about each entity. */
export class EntityBook {
  private seen = new Map<string, Seen>();
  private titles = new Map<string, string>();

  constructor(roster: { name: string; title: string }[] = []) {
    for (const u of roster) this.titles.set(u.name.toLowerCase(), u.title);
  }

  private touch(kind: EntityKind, name: string, ms: number, facts: Record<string, string | number | undefined | null>): string {
    const id = entityId(kind, name);
    let s = this.seen.get(id);
    if (!s) {
      s = { entity: { id, kind, name, info: {} }, lastSeenMs: ms };
      this.seen.set(id, s);
    }
    if (ms > s.lastSeenMs) s.lastSeenMs = ms;
    for (const [k, v] of Object.entries(facts)) {
      if (v === undefined || v === null || v === "") continue;
      if (s.entity.info[k] === undefined) s.entity.info[k] = String(v);
    }
    return id;
  }

  /** Records the event's entities; returns their ids. */
  add(ev: TelemetryEvent, log?: NativeLog, row?: KqlRow): string[] {
    const ms = Date.parse(ev.ts);
    const ids: string[] = [];
    const account = accountOf(ev);
    if (account) {
      const upn = account.includes("@") ? account : undefined;
      ids.push(this.touch("account", account, ms, {
        UPN: upn, "Display name": ev.user?.full_name, Department: ev.user?.department ?? departmentOf(ev, log),
        Title: ev.user?.title ?? ev.user_title ?? this.titles.get(account.split("@")[0].split("\\").pop() ?? account),
      }));
    }
    if (ev.hostname && ev.hostname !== "-") {
      ids.push(this.touch("host", shortHost(ev.hostname), ms, { "Host name": ev.hostname, OS: hostOs(ev, log), IP: hostIp(ev, row) }));
    }
    const geo = ev.geo;
    const geoFacts = geo ? {
      Country: geo.country, City: geo.city, ASN: geo.asn, "AS organization": geo.as_org, ISP: geo.isp,
      Location: geo.latitude !== undefined && geo.longitude !== undefined ? `${geo.latitude}, ${geo.longitude}` : undefined,
      Anonymizer: geo.anonymous ? "Yes" : undefined,
    } : {};
    if (ev.src_ip && IPV4.test(ev.src_ip)) ids.push(this.touch("ip", ev.src_ip, ms, { Address: ev.src_ip, Scope: isPrivateIp(ev.src_ip) ? "Internal" : "External", ...geoFacts }));
    if (ev.dst_ip && IPV4.test(ev.dst_ip)) ids.push(this.touch("ip", ev.dst_ip, ms, { Address: ev.dst_ip, Scope: isPrivateIp(ev.dst_ip) ? "Internal" : "External" }));
    if (ev.file?.name || ev.file?.path) {
      const name = ev.file.name ?? ev.file.path.split(/[\\/]/).pop()!;
      ids.push(this.touch("file", name, ms, { Path: ev.file.path, SHA256: ev.file.sha256, MD5: ev.file.md5, Size: ev.file.size }));
    }
    if (ev.process?.name) {
      ids.push(this.touch("process", `${ev.process.name} (${ev.process.pid})`, ms, {
        "Command line": ev.process.cmdline, Path: ev.process.path, "Parent process": ev.process.parent_name, PID: ev.process.pid, SHA256: ev.process.hash?.sha256, Host: ev.hostname,
      }));
    }
    if (ev.network?.url) ids.push(this.touch("url", ev.network.url, ms, { URL: ev.network.url, Domain: ev.network.domain }));
    const domain = ev.network?.domain ?? ev.dns?.query;
    if (domain) ids.push(this.touch("domain", domain.replace(/\.$/, ""), ms, { Domain: domain.replace(/\.$/, ""), Response: ev.dns?.response }));
    if (ev.event_type.startsWith("email_") && account?.includes("@")) {
      ids.push(this.touch("mailbox", account, ms, { "Mailbox address": account, "Display name": ev.user?.full_name }));
    }
    if (ev.cloud?.resource) {
      const azure = ev.source === "cloud_azure" || /^\/subscriptions\//i.test(ev.cloud.resource);
      ids.push(this.touch(azure ? "azureresource" : "cloudapp", ev.cloud.resource, ms, { Service: ev.cloud.service, Region: ev.cloud.region, Provider: ev.cloud.provider }));
    }
    if (ev.registry?.path || ev.registry?.key) {
      const key = (ev.registry.path ?? ev.registry.key)!;
      ids.push(this.touch("registry", key, ms, { Key: key, Value: ev.registry.value }));
    }
    return [...new Set(ids)];
  }

  /**
   * An indicator an analyst wrote on an escalation, as the entity it names (an IP, a domain, a URL,
   * an account, a host, a file by its hash or path, a registry key). Null for what no entity holds
   * (a command line, a process image). Facts say it came from the analyst.
   */
  addIndicator(type: string, value: string, ms: number): string | null {
    const v = value.trim();
    if (!v) return null;
    const by = { "Named in escalation": "Yes" };
    switch (type) {
      case "ip": { const ip = v.split(":")[0]; return IPV4.test(ip) ? this.touch("ip", ip, ms, { Address: ip, Scope: isPrivateIp(ip) ? "Internal" : "External", ...by }) : null; }
      case "domain": return this.touch("domain", v.replace(/\.$/, "").toLowerCase(), ms, { Domain: v.replace(/\.$/, ""), ...by });
      case "url": return this.touch("url", v, ms, { URL: v, ...by });
      case "email": return NON_USERS.test(v) ? null : this.touch("account", v.toLowerCase(), ms, { UPN: v.toLowerCase(), ...by });
      case "host": return this.touch("host", shortHost(v), ms, { "Host name": v, ...by });
      case "sha256": case "sha1": case "md5": return this.touch("file", v.toLowerCase(), ms, { [type.toUpperCase()]: v.toLowerCase(), ...by });
      case "file_path": return this.touch("file", v.split(/[\\/]/).pop() || v, ms, { Path: v, ...by });
      case "registry": return this.touch("registry", v, ms, { Key: v, ...by });
      default: return null;
    }
  }

  /** The finished entities named by these ids, with "Last seen" filled in. */
  resolve(ids: Iterable<string>): Record<string, SentinelEntity> {
    const out: Record<string, SentinelEntity> = {};
    for (const id of ids) {
      const s = this.seen.get(id);
      if (!s) continue;
      out[id] = { ...s.entity, info: { ...s.entity.info, "Last seen": new Date(s.lastSeenMs).toISOString() } };
    }
    return out;
  }
}

const ENTITY_TYPE: Record<EntityKind, string> = {
  account: "account", host: "host", ip: "ip", file: "file", process: "process", url: "url", domain: "dns", mailbox: "mailbox", cloudapp: "cloud-application", azureresource: "azure-resource", registry: "registry-key",
};

/** The Entities column of a SecurityAlert row: a JSON array, as the product writes it. */
export function entitiesColumn(entities: SentinelEntity[]): string {
  return JSON.stringify(entities.map((e, i) => {
    const base: Record<string, unknown> = { $id: String(i + 2), Type: ENTITY_TYPE[e.kind] };
    switch (e.kind) {
      case "account": {
        const [name, suffix] = e.name.split("@");
        return { ...base, Name: name, UPNSuffix: suffix };
      }
      case "host": return { ...base, HostName: e.name };
      case "ip": return { ...base, Address: e.name };
      case "file": return { ...base, Name: e.name, Directory: e.info.Path };
      case "process": return { ...base, CommandLine: e.info["Command line"], ProcessId: e.info.PID };
      case "url": return { ...base, Url: e.name };
      case "domain": return { ...base, DomainName: e.name };
      case "mailbox": return { ...base, MailboxPrimaryAddress: e.name };
      case "azureresource": return { ...base, ResourceId: e.name };
      case "cloudapp": return { ...base, Name: e.name };
      case "registry": return { ...base, Key: e.name };
    }
  }));
}

/** Graph evidence as the Entities column of the SecurityAlert row: one entity per evidence entry. */
export function graphEntitiesColumn(evidence: Record<string, unknown>[]): string {
  const out: Record<string, unknown>[] = [];
  evidence.forEach((e, i) => {
    const base = { $id: String(i + 2) };
    const kind = String(e["@odata.type"] ?? "").split(".").pop();
    const account = e.userAccount as { accountName?: string; userPrincipalName?: string } | undefined;
    switch (kind) {
      case "deviceEvidence": out.push({ ...base, Type: "host", HostName: e.hostName ?? e.deviceDnsName }); break;
      case "userEvidence": { const [name, suffix] = String(account?.userPrincipalName ?? account?.accountName ?? "").split("@"); out.push({ ...base, Type: "account", Name: name, UPNSuffix: suffix }); break; }
      case "mailboxEvidence": out.push({ ...base, Type: "mailbox", MailboxPrimaryAddress: e.primaryAddress }); break;
      case "ipEvidence": out.push({ ...base, Type: "ip", Address: e.ipAddress }); break;
      case "urlEvidence": out.push({ ...base, Type: "url", Url: e.url }); break;
      case "fileEvidence": out.push({ ...base, Type: "file", Name: (e.fileDetails as { fileName?: string } | undefined)?.fileName }); break;
      case "processEvidence": out.push({ ...base, Type: "process", CommandLine: e.processCommandLine, ProcessId: e.processId }); break;
      default: out.push({ ...base, Type: kind ?? "unknown" });
    }
  });
  return JSON.stringify(out);
}
