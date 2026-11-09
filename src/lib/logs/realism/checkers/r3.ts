/**
 * R3 One identity, one id. Scope: one company's feed (live, team, xdr: everything one learner sees
 * for that company), one scenario, one room.
 *  a. One SID per account and one account per SID (pairs read from the record: XSid beside XName).
 *  b. One object id per UPN and one UPN per object id (Entra userId, MDE AccountObjectId, Okta id).
 *  c. One IP per host and one host per IP (the record's own host field beside its own-IP field).
 *  d. User name convention: a company user written two ways (j.chen and jchen, or john.chen).
 *  e. Iron rule: a row of one company naming another company's domain, realm, host, person or
 *     office address.
 */
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import { isNonHumanAccount } from "@/lib/sim/nonHuman";
import type { Checker, LogRow, Violation } from "../types";
import { leaves, stringLeaves } from "../util";
import { COMPANIES } from "../collectors/live";

const scopeOf = (r: LogRow) => (r.surface === "scenario" || r.surface === "room" || r.surface === "edr" || r.surface === "forensic" ? `${r.surface}:${r.storyId}` : `${r.surface}:${r.company}`);

/** [id key suffix, name key suffix] pairs read under one parent object. */
const SID_PAIRS: [RegExp, (k: string) => string[]][] = [
  [/Sid$/, k => [k.replace(/Sid$/, "Name"), k.replace(/UserSid$/, "UserName"), k.replace(/Sid$/, "")]],
  [/SID$/, k => [k.replace(/SID$/, "Name"), k.replace(/SID$/, "")]],
];
const OBJ_PAIRS: [string, string][] = [
  ["userId", "userPrincipalName"], ["AccountObjectId", "AccountUpn"], ["UserId", "UserPrincipalName"], ["InitiatingProcessAccountObjectId", "InitiatingProcessAccountUpn"],
  ["id", "alternateId"], ["objectId", "userPrincipalName"],
];
const HOST_IP: [string, string][] = [
  ["ComputerName", "LocalAddressIP4"], ["DeviceName", "LocalIP"], ["agentComputerName", "agentIpV4"], ["Computer", "ComputerIP"],
  ["host.name", "host.ip"], ["hostname", "host_ip"],
];

const samOf = (name: string) => name.replace(/^CN=([^,]+),.*$/i, "$1").split("\\").pop()!.split("@")[0].trim().toLowerCase();
const hostKey = (h: string) => h.trim().toLowerCase().split(".")[0];
const SKIP_NAME = /^(-|system|local service|network service|anonymous logon|n\/a|null|unknown|)$/i;

/** Values of a record keyed by full path (array indices already collapsed by leaves()). */
function pathMap(r: LogRow): Map<string, string> {
  const m = new Map<string, string>();
  if (typeof r.raw === "string") return m;
  for (const [p, v] of leaves(r.raw)) if (typeof v === "string" || typeof v === "number") if (!m.has(p)) m.set(p, String(v));
  return m;
}
const parentOf = (p: string) => (p.includes(".") ? p.slice(0, p.lastIndexOf(".") + 1) : "");
const leafOf = (p: string) => p.slice(p.lastIndexOf(".") + 1);

type Book = Map<string, Map<string, Set<string>>>;
const note = (b: Book, scope: string, a: string, z: string) => {
  const m = b.get(scope) ?? b.set(scope, new Map()).get(scope)!;
  (m.get(a) ?? m.set(a, new Set()).get(a)!).add(z);
};

export const r3: Checker = c => {
  const out: Violation[] = [];
  const sidByName: Book = new Map(), nameBySid: Book = new Map();
  // One book per identity provider: an Okta user id (00u...) and an Entra object id are two IdPs' ids for one person, not two ids in one directory.
  const oidByUpn: Book = new Map(), upnByOid: Book = new Map(), oktaByUpn: Book = new Map();
  const ipByHost: Book = new Map(), hostByIp: Book = new Map();
  const example = new Map<string, string>();
  const meta = new Map<string, LogRow>();

  for (const r of c.rows) {
    if (typeof r.raw === "string") continue;
    const scope = scopeOf(r);
    meta.set(scope, r);
    const pm = pathMap(r);
    for (const [p, v] of pm) {
      const leaf = leafOf(p), par = parentOf(p);
      if (/^S-1-5-21-\d+-\d+-\d+-\d+$/.test(v)) {
        for (const [re, names] of SID_PAIRS) if (re.test(leaf)) {
          const nk = names(leaf).map(n => pm.get(par + n)).find(x => x !== undefined);
          if (!nk || SKIP_NAME.test(nk) || nk.endsWith("$")) continue;
          const sam = samOf(nk);
          if (!sam || SKIP_NAME.test(sam) || /^s-1-\d/.test(sam)) continue;
          note(sidByName, scope, sam, v); note(nameBySid, scope, v, sam);
          example.set(`${scope}|${sam}|${v}`, r.rowId);
        }
      }
    }
    for (const [idk, upk] of OBJ_PAIRS) for (const [p, v] of pm) {
      if (leafOf(p) !== idk) continue;
      const upn = pm.get(parentOf(p) + upk);
      if (!upn || !upn.includes("@") || !v || v === "-") continue;
      const u = upn.toLowerCase();
      note(idk === "id" ? oktaByUpn : oidByUpn, scope, u, v); note(upnByOid, scope, v, u);
      example.set(`${scope}|${u}|${v}`, r.rowId);
    }
    for (const [hk, ik] of HOST_IP) for (const [p, v] of pm) {
      if (leafOf(p) !== leafOf(hk) || !p.endsWith(hk)) continue;
      const ip = pm.get(p.slice(0, p.length - hk.length) + ik);
      if (!ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip) || ip === "127.0.0.1" || ip === "0.0.0.0") continue;
      const h = hostKey(v);
      if (!h || h === "-") continue;
      note(ipByHost, scope, h, ip); note(hostByIp, scope, ip, h);
      example.set(`${scope}|${h}|${ip}`, r.rowId);
    }
  }

  const emit = (b: Book, what: string, swap = false) => {
    for (const [scope, m] of b) for (const [a, zs] of m) {
      if (zs.size < 2) continue;
      const list = [...zs].sort();
      const r = meta.get(scope)!;
      const ex = list.map(z => example.get(swap ? `${scope}|${z}|${a}` : `${scope}|${a}|${z}`)).filter(Boolean).slice(0, 2).join(", ");
      out.push({ surface: r.surface, rule: "R3", rowId: `${scope}:${a}`, detail: what, company: r.company, example: `${list.join(", ")} (${ex})` });
    }
  };
  emit(sidByName, "account has more than one SID");
  emit(nameBySid, "SID names more than one account", true);
  emit(oidByUpn, "UPN has more than one object id");
  emit(oktaByUpn, "UPN has more than one object id");
  emit(upnByOid, "object id names more than one UPN", true);
  emit(ipByHost, "host has more than one IP");
  emit(hostByIp, "IP shared by more than one host", true);

  // d. naming convention, e. cross-company tokens
  const tokens = crossCompanyTokens();
  const conv = new Set<string>();
  const leak = new Set<string>();
  for (const r of c.rows) {
    const company = r.company;
    if (!company || !COMPANY_ASSETS[company]) continue;
    const a = COMPANY_ASSETS[company];
    const roster = new Map(a.roster.map(p => [p.name.replace(/[._-]/g, ""), p.name]));
    const initials = new Map(a.roster.filter(p => /^[a-z]\.[a-z-]+$/.test(p.name)).map(p => [p.name.split(".")[1], p.name]));
    const text = stringLeaves(r).map(([, v]) => v).join("\n");
    const dom = a.domain.replace(/\./g, "\\.");
    for (const m of text.matchAll(new RegExp(`([a-z0-9][a-z0-9._-]*)@${dom}`, "gi"))) {
      const local = m[1].toLowerCase();
      if (isNonHumanAccount(local) || roster.has(local.replace(/[._-]/g, "")) && roster.get(local.replace(/[._-]/g, "")) === local) continue;
      const same = roster.get(local.replace(/[._-]/g, ""));
      const full = /^([a-z]{2,})\.([a-z-]+)$/.exec(local);
      const viaInitial = full ? initials.get(full[2]) : undefined;
      const canon = same ?? (viaInitial && viaInitial[0] === full![1][0] ? viaInitial : undefined);
      if (!canon || canon === local) continue;
      const k = `${r.surface}|${company}|${local}`;
      if (conv.has(k)) continue;
      conv.add(k);
      out.push({ surface: r.surface, rule: "R3", rowId: `${r.surface}:${company}:${local}`, detail: `user ${local} breaks the convention of ${canon}`, company, example: r.rowId });
    }
    for (const t of tokens) {
      if (t.company === company) continue;
      if (!t.re.test(text)) continue;
      const scope = r.surface === "live" || r.surface === "team" || r.surface === "xdr" ? `${r.surface}:${company}:${r.storyId ?? ""}` : `${r.surface}:${r.storyId}`;
      const k = `${scope}|${t.token}`;
      if (leak.has(k)) continue;
      leak.add(k);
      out.push({ surface: r.surface, rule: "R3", rowId: scope, detail: `names ${t.company} ${t.kind} ${t.token}`, company, example: r.rowId });
    }
  }
  return out;
};

interface Token { company: string; kind: string; token: string; re: RegExp }
let tokenCache: Token[] | null = null;
function crossCompanyTokens(): Token[] {
  if (tokenCache) return tokenCache;
  const raw: { company: string; kind: string; token: string }[] = [];
  for (const id of COMPANIES) {
    const a = COMPANY_ASSETS[id];
    raw.push({ company: id, kind: "domain", token: a.domain });
    raw.push({ company: id, kind: "realm", token: a.netbios });
    for (const h of new Set([...a.hosts, a.dc, a.fileServer])) raw.push({ company: id, kind: "host", token: h });
    for (const p of a.roster) if (p.name.includes(".")) raw.push({ company: id, kind: "user", token: p.name });
    if (a.office?.ip) raw.push({ company: id, kind: "office IP", token: a.office.ip });
  }
  const owners = new Map<string, Set<string>>();
  for (const t of raw) (owners.get(t.token.toLowerCase()) ?? owners.set(t.token.toLowerCase(), new Set()).get(t.token.toLowerCase())!).add(t.company);
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  tokenCache = raw.filter(t => owners.get(t.token.toLowerCase())!.size === 1 && t.token.length >= 5)
    .map(t => ({ ...t, re: new RegExp(`(?<![\\w.-])${esc(t.token)}(?![\\w-])`, t.kind === "realm" ? "" : "i") }));
  return tokenCache;
}
