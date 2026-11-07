/**
 * Who and what exists in the session: one record per person and per host, the single truth every table
 * follows. Built from public inputs only: company data, the session's identity, and the feed so far.
 *
 * The feed decides where it speaks (a person's workstation, a host's address, a department a product
 * states); otherwise the value is derived from the identity alone, the same way for everyone.
 */
import type { NativeIdentity } from "@/lib/logs/native";
import type { KqlRow } from "@/lib/kql/types";
import { nameFromLogin } from "@/lib/logs/native/sources/_identity-common";
import { accountSid, hostIpFor } from "@/lib/logs/native/sources/_proc-identity";
import type { NativeCtx } from "@/lib/logs/native/types";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import type { TelemetryEvent } from "@/lib/sim/types";
import { deptOf, tenantRoster, type Dept, type Tenant } from "@/lib/team/tenant";
import { isServerHost } from "@/lib/edr/hostBaseline";

export type HostOs = "Windows" | "WindowsServer" | "Linux" | "macOS" | "Appliance";

export interface Person {
  /** Lower-case UPN: the key across every table. */
  upn: string;
  /** The account's SID: what the feed prints for it, else what the native modules derive. */
  sid: string;
  /** Left of the @, as the records print the account. */
  name: string;
  display: string;
  title: string;
  department: string;
  /** Automation account: no person behind it. */
  service: boolean;
  /** Usual workstation: where the feed puts them, else assigned from the inventory. */
  host: string;
  /** No baseline history: the account does not exist before the session (created in it, or never resolved). */
  noHistory: boolean;
}

export interface Host {
  name: string;
  /** Lower-case short name: the key across every table. */
  key: string;
  os: HostOs;
  server: boolean;
  ip: string;
  /** Other addresses the feed printed for this host. */
  otherIps: string[];
  /** Who logs on here, as in DeviceInfo.LoggedOnUsers. */
  users: string[];
}

export interface Directory {
  people: Map<string, Person>;
  hosts: Map<string, Host>;
  domain: string;
}

const DEPT_LABEL: Record<Dept, string> = {
  it: "IT", eng: "Engineering", finance: "Finance", hr: "Human Resources", legal: "Legal", sales: "Sales", exec: "Executive", ops: "Operations", general: "General",
};

const WORKSTATION_SOURCES = new Set(["edr", "sysmon", "av", "windows_security", "ad", "firewall", "proxy", "dns", "linux_audit", "dlp"]);
const HOST_IP_SOURCES = new Set(["edr", "sysmon", "av", "windows_security", "linux_audit", "firewall", "proxy", "dns"]);
const PRIVATE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;
const NON_PEOPLE = /^(system|local service|network service|anonymous logon|unknown|n\/a|-|none)$/i;
const SERVICE = /^(svc[-._]|ci-|.*[-._]svc$|.*-service$|dc-replication)/i;

/** A service endpoint written in the host field (aad.<tenant>, the identity provider): not a machine. */
const SERVICE_LABEL = /^(aad|login|sts|graph|outlook|mail|smtp|www|api|portal|sso)\./;

export const hostKeyOf = (h: string) => h.trim().toLowerCase().split(".")[0];

/** A record's display name, when it is really this account's: the surname matches the account name. */
function ownsName(display: string, local: string): boolean {
  const d = display.toLowerCase();
  return d === local || d.split(" ").pop() === local.split(/[._-]/).pop();
}

/** A session's own hostname: not a cloud endpoint someone wrote in the host field. */
export function isOwnHost(name: string, domain: string, companyDomain: string): boolean {
  if (!name.includes(".")) return true;
  const n = name.toLowerCase();
  if (SERVICE_LABEL.test(n)) return false;
  if (n.endsWith(".local") || n.endsWith(`.${domain}`) || n.endsWith(`.${companyDomain}`)) return true;
  return false;
}

function osOf(name: string, evidence?: HostOs): HostOs {
  if (evidence) return evidence;
  const n = name.toLowerCase();
  if (/^(esx|vcsa|vcenter|badge|printer|cam-|nas-|app\.|sql-)/.test(n)) return "Appliance";
  if (/macbook|^mac-/.test(n)) return "macOS";
  if (/linux|lnx|k8s|prod-srv|ubuntu|rhel|db-prod/.test(n)) return "Linux";
  return isServerHost({ name }) ? "WindowsServer" : "Windows";
}

const hash = (s: string) => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; };

/** The inventory the session starts from: the company's, or, in a named organization, its own people. */
function seedDirectory(companyId: string, ctx: NativeCtx, identity?: NativeIdentity) {
  const a = COMPANY_ASSETS[companyId];
  if (!a) return { people: [] as { upn: string; title: string; display?: string; service: boolean }[], hosts: [] as string[] };
  const hosts = [...new Set([...a.hosts, a.dc, a.fileServer])];
  const svc = a.serviceAccounts.map(s => ({ upn: `${s}@${ctx.domain}`.toLowerCase(), title: "Service Account", service: true }));
  if (!identity) return { people: [...a.roster.map(r => ({ upn: `${r.name}@${ctx.domain}`.toLowerCase(), title: r.title, service: false })), ...svc], hosts };
  // A named organization never shows the template's people or host codes.
  const stem = a.domain.split(".")[0];
  const tenant = { domain: identity.domain } as Tenant;
  const roster = tenantRoster(a.roster.map(r => ({ email: `${r.name}@${a.domain}`, title: r.title })), tenant, `directory:${identity.domain}`);
  const code = /^(?:SRV|SVR)-([A-Z]{2,5})-/.exec(a.dc)?.[1] ?? /^(?:SRV|SVR)-([A-Z]{2,5})-/.exec(a.fileServer)?.[1];
  const tcode = identity.netbios.replace(/[^A-Z]/g, "").padEnd(3, "X").slice(0, 3);
  const swap = (h: string) => (code ? h.replace(`-${code}-`, `-${tcode}-`) : h).replace(new RegExp(stem, "gi"), identity.domain.split(".")[0]);
  return {
    people: [...[...roster.values()].map(p => ({ upn: p.email.toLowerCase(), title: p.title, display: p.name, service: false })), ...svc],
    hosts: hosts.map(swap),
  };
}

/** What the feed says about the session's people and hosts. Rows are scanned too: a record can name an account the event does not. */
export function buildDirectory(events: TelemetryEvent[], rowsOf: (id: string) => KqlRow[], companyId: string, ctx: NativeCtx, identity?: NativeIdentity): Directory {
  const domain = ctx.domain.toLowerCase();
  const companyDomain = (COMPANY_ASSETS[companyId]?.domain ?? domain).toLowerCase();
  const seed = seedDirectory(companyId, ctx, identity);
  const roster = new Map<string, { title: string; display?: string; service: boolean }>(seed.people.map(p => [p.upn, p]));

  interface Seen { sid?: string; title?: string; display?: string; department?: string; workstation?: string; firstHost?: string; ok: boolean; created: boolean; missing: boolean }
  const seen = new Map<string, Seen>();
  const hostSeen = new Map<string, { name: string; ip?: string; others: Set<string>; os?: HostOs }>();
  const touch = (upn: string) => { let s = seen.get(upn); if (!s) { s = { ok: false, created: false, missing: false }; seen.set(upn, s); } return s; };
  const addHost = (name: string) => {
    const key = hostKeyOf(name);
    let h = hostSeen.get(key);
    if (!h) { h = { name: name.split(".")[0], others: new Set() }; hostSeen.set(key, h); }
    return h;
  };
  for (const h of seed.hosts) addHost(h);

  const own = (u: string) => u.endsWith(`@${domain}`) && !u.includes("#ext#") && !u.includes("\\");

  for (const ev of events) {
    const ownHost = ev.hostname && isOwnHost(ev.hostname, domain, companyDomain) ? ev.hostname : undefined;
    if (ownHost) {
      const h = addHost(ownHost);
      if (ev.src_ip && PRIVATE.test(ev.src_ip) && HOST_IP_SOURCES.has(ev.source)) {
        if (!h.ip) h.ip = ev.src_ip;
        else if (h.ip !== ev.src_ip) h.others.add(ev.src_ip);
      }
      if (!h.os && (ev.source === "linux_audit" || ev.process?.path?.startsWith("/"))) h.os = "Linux";
    }
    const email = (ev.user_email ?? ev.user?.email)?.toLowerCase();
    const upns = new Set<string>();
    if (email && own(email) && !NON_PEOPLE.test(email)) upns.add(email);
    for (const row of rowsOf(ev.id)) {
      for (const c of ["AccountUpn", "InitiatingProcessAccountUpn", "UserPrincipalName", "OriginalActorAlternateId", "UserId", "ActorEmail", "RecipientEmailAddress"]) {
        const v = row[c];
        if (typeof v === "string" && v.includes("@") && own(v.toLowerCase())) upns.add(v.toLowerCase());
      }
    }
    for (const upn of upns) {
      const s = touch(upn);
      for (const row of rowsOf(ev.id)) {
        if (!s.sid) {
          const local = upn.split("@")[0];
          for (const [name, sid] of [[row.AccountName, row.AccountSid], [row.TargetUserName, row.TargetUserSid]]) {
            if (typeof sid === "string" && /^S-1-5-21-/.test(sid) && low(name).replace(/\./g, "") === local.replace(/\./g, "")) s.sid = sid;
          }
        }
        const named = row.UserDisplayName ?? row.ActorDisplayName;
        if (typeof named === "string" && named && low(row.UserPrincipalName ?? row.OriginalActorAlternateId) === upn && ownsName(named, upn.split("@")[0]) && (!s.display || named.includes(" "))) s.display ??= named;
      }
      if (upn === email) {
        s.title ??= ev.user?.title ?? ev.user_title;
        s.display ??= ev.user?.full_name;
        s.department ??= ev.user?.department ?? departmentIn(ev, rowsOf(ev.id));
        if (ownHost && WORKSTATION_SOURCES.has(ev.source)) {
          s.firstHost ??= ownHost;
          if (!isServerHost({ name: ownHost }) && osOf(ownHost) !== "Appliance") s.workstation ??= ownHost;
        }
      }
      const rows = rowsOf(ev.id);
      const failedLookup = rows.some(r => String(r.ResultType) === "50034" || /USER_NOT_FOUND|0xC0000064/i.test(`${r.EventOriginalResultDetails ?? ""} ${r.SubStatus ?? ""}`));
      if (failedLookup) s.missing = true; else if (!/fail|denied/.test(ev.event_type)) s.ok = true;
    }
    // An account the session itself creates has no history before it.
    for (const row of rowsOf(ev.id)) {
      if (row.EventID === 4720 && typeof row.TargetUserName === "string") touch(`${row.TargetUserName.toLowerCase()}@${domain}`).created = true;
      if (row.OperationName === "Add user" || row.OperationName === "Invite external user") {
        const t = (row.TargetResources as { userPrincipalName?: string }[] | undefined)?.[0]?.userPrincipalName?.toLowerCase();
        if (t && own(t)) touch(t).created = true;
      }
    }
  }

  const hosts = new Map<string, Host>();
  for (const [key, h] of hostSeen) {
    hosts.set(key, { name: h.name, key, os: osOf(h.name, h.os), server: isServerHost({ name: h.name }), ip: h.ip ?? hostIpFor(ctx, h.name), otherIps: [...h.others], users: [] });
  }
  // Assignment draws on the inventory alone, which the feed does not change: a poll never reshuffles it.
  const inventory = seed.hosts.map(h => hosts.get(hostKeyOf(h))).filter((h): h is Host => !!h && h.os !== "Appliance");
  const workstations = inventory.filter(h => !h.server).map(h => h.name).sort();
  const servers = inventory.filter(h => h.server).map(h => h.name).sort();

  const people = new Map<string, Person>();
  for (const upn of new Set([...roster.keys(), ...seen.keys()])) {
    const d = roster.get(upn);
    const s = seen.get(upn);
    const local = upn.split("@")[0];
    const service = d?.service ?? SERVICE.test(local);
    const title = s?.title ?? d?.title ?? (service ? "Service Account" : "");
    const fallback = (service ? servers : workstations);
    const pool = fallback.length ? fallback : workstations.length ? workstations : servers;
    const assigned = pool.length ? pool[hash(upn) % pool.length] : "";
    people.set(upn, {
      upn, sid: s?.sid ?? accountSid(ctx, local), name: local, display: s?.display ?? d?.display ?? nameFromLogin(upn), title, department: s?.department ?? (service ? "IT" : DEPT_LABEL[deptOf(title)]), service,
      host: s?.workstation ?? (service ? s?.firstHost : undefined) ?? assigned,
      noHistory: !!s && !d && (s.created || (s.missing && !s.ok)),
    });
  }
  for (const p of people.values()) {
    const h = hosts.get(hostKeyOf(p.host));
    if (h && !p.noHistory) h.users.push(p.upn);
  }
  for (const h of hosts.values()) h.users.sort();
  return { people, hosts, domain };
}

const low = (v: unknown) => String(v ?? "").toLowerCase();

/** One display name per person: the few feed records that print another name follow the directory. */
export function alignNames(dir: Directory, tables: Record<string, { rows: KqlRow[] }>): number {
  let changed = 0;
  for (const r of tables.SigninLogs?.rows ?? []) {
    const p = dir.people.get(low(r.UserPrincipalName));
    if (p && r.UserDisplayName !== p.display) { r.UserDisplayName = p.display; r.Identity = p.display; changed++; }
  }
  for (const r of tables.OktaV2_CL?.rows ?? []) {
    const p = dir.people.get(low(r.OriginalActorAlternateId));
    if (p && r.ActorDisplayName !== p.display) { r.ActorDisplayName = p.display; changed++; }
  }
  return changed;
}

function departmentIn(ev: TelemetryEvent, rows: KqlRow[]): string | undefined {
  const raw = ev.raw as Record<string, unknown> | undefined;
  const v = raw?.["purview.Department"] ?? raw?.["user.department"];
  if (typeof v === "string" && v) return v;
  const zia = rows.find(r => r.DeviceVendor === "Zscaler")?.DeviceCustomString1;
  return typeof zia === "string" && zia ? zia : undefined;
}
