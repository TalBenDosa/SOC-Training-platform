// Full correlation with the scenario: any query about anyone in the session gets a real answer, and the
// tables agree with each other and with the feed. Every session runs on the Sentinel stack, through the
// engine, under the default 24 hour range. Answer data is used only here, in the test.
import { writeFileSync } from "fs";
import { afterAll, describe, expect, it } from "vitest";
import { runKql } from "@/lib/kql";
import type { KqlRow } from "@/lib/kql/types";
import { graphAlertFor, stackFor, withoutDetectionFeed, type Stack } from "@/lib/logs/native";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { stackForConsole } from "@/lib/team/investigationConsole";
import { teamLoad } from "@/lib/team/load";
import { parseTenant, TENANT_TEMPLATE, tenantIdentity, type Tenant } from "@/lib/team/tenant";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import type { TelemetryEvent } from "@/lib/sim/types";
import { hostKeyOf, isOwnHost } from "./directory";
import { identityColumns } from "./fallback";
import { plain } from "./rules";
import { entityInsights, incidentInsights } from "./insights";
import { buildWorkspace, type BuildOptions, type SentinelWorkspaceBuild } from "./workspace";

const COMPANIES = ["nexacorp", "medcore", "rocketstack", "globallogis", "quantumbank"];
const DIFFS = ["easy", "medium", "hard"] as const;
const SEEDS = ["a", "b"];
const roster = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
const SESSION_STACK: Stack = stackForConsole({}, "sentinel");
/** What the builders pass: useTeamSentinel and useSentinelIncidents strip the detection feed. */
const STACK: Stack = withoutDetectionFeed(SESSION_STACK);
const PRIVATE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const DOC_IP = /^(192\.0\.2|198\.51\.100|203\.0\.113)\./;
const isAttack = (a?: Record<string, unknown>) => a?.expected_verdict === "tp" || a?.expected_verdict === "escalate";

interface Session {
  key: string; company: string; events: TelemetryEvent[]; answers: Map<string, Record<string, unknown>>; opts: BuildOptions; ws: SentinelWorkspaceBuild;
  env: { tables: SentinelWorkspaceBuild["tables"]; now: Date; timeRange: { from: Date; to: Date } };
}

function open(company: string, diff: (typeof DIFFS)[number], seed: string, tenant: Tenant | null = null): Session {
  const tl = buildTeamTimeline(company, diff, `corr-${seed}-${company}`, null, teamLoad(diff, roster), SESSION_STACK, tenant).filter(t => t.channel === "feed");
  const events = tl.map(t => t.body as unknown as TelemetryEvent);
  const opts: BuildOptions = { companyId: company, stack: STACK, ...(tenant ? { identity: tenantIdentity(tenant), orgName: tenant.name } : {}) };
  const ws = buildWorkspace(events, opts);
  const now = new Date(ws.now);
  return {
    key: `${tenant ? tenant.name : company}/${diff}/${seed}`, company, events, answers: new Map(tl.map(t => [(t.body as unknown as TelemetryEvent).id, (t.answer ?? {}) as Record<string, unknown>])), opts, ws,
    env: { tables: ws.tables, now, timeRange: { from: new Date(now.getTime() - 86_400_000), to: now } },
  };
}

const q = (s: Session, query: string) => {
  const r = runKql(query, s.env);
  if (!r.ok) throw new Error(`${r.error.message}: ${query}`);
  return r.rows;
};
const kq = (v: string) => `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

const tenant = parseTenant("acme-labs") as Tenant;
const SESSIONS: [string, () => Session][] = [
  ...COMPANIES.flatMap(c => DIFFS.flatMap(d => SEEDS.map(s => [`${c}/${d}/${s}`, () => open(c, d, s)] as [string, () => Session]))),
  ...DIFFS.flatMap(d => SEEDS.map(s => [`named/${d}/${s}`, () => open(TENANT_TEMPLATE, d, s, tenant)] as [string, () => Session])),
];

const counts: Record<string, Record<string, number>> = {};
const ruleHits = new Set<string>();
const tally = (s: Session, name: string, n = 1) => { const k = s.key.split("/")[0]; (counts[k] ??= {})[name] = ((counts[k] ??= {})[name] ?? 0) + n; };

afterAll(() => { if (process.env.CORR_OUT) writeFileSync(process.env.CORR_OUT, JSON.stringify({ counts, ruleHits: [...ruleHits] }, null, 1)); });

const low = (v: unknown) => String(v ?? "").toLowerCase();
const short = (h: string) => hostKeyOf(h);

for (const [name, make] of SESSIONS) {
  describe(name, () => {
    const s = make();
    const dir = s.ws.directory!;
    const eff = stackFor(s.company, STACK);
    const okta = eff.idp === "okta";
    const google = eff.collab === "google_workspace";
    const domain = (s.opts.identity?.domain ?? COMPANY_ASSETS[s.company].domain).toLowerCase();
    const ownDomain = (u: string) => u.toLowerCase().endsWith(`@${domain}`) && !u.includes("#EXT#");

    it("every person answers: sign-ins, inventory, logons on their host, mail and files", () => {
      const missing: string[] = [];
      // An independent list: the feed's own users, plus the company directory.
      const expected = new Set(s.events.map(e => (e.user_email ?? e.user?.email)?.toLowerCase()).filter((u): u is string => !!u && ownDomain(u)));
      if (!s.opts.identity) for (const r of COMPANY_ASSETS[s.company].roster) expected.add(`${r.name}@${domain}`);
      for (const u of expected) if (!dir.people.has(u)) missing.push(`not in the directory: ${u}`);
      for (const p of dir.people.values()) {
        tally(s, "people");
        const inv = q(s, `IdentityInfo | where AccountUPN =~ ${kq(p.upn)}`);
        if (inv.length !== 1) missing.push(`${p.upn}: IdentityInfo rows ${inv.length}`);
        if (p.noHistory) { tally(s, "people without history"); continue; }
        const signin = okta ? `OktaV2_CL | where OriginalActorAlternateId =~ ${kq(p.upn)}` : `SigninLogs | where UserPrincipalName =~ ${kq(p.upn)}`;
        if (!q(s, signin).length) missing.push(`${p.upn}: no sign-ins`);
        const office = google ? `GoogleWorkspaceReports | where ActorEmail =~ ${kq(p.upn)}` : `OfficeActivity | where UserId =~ ${kq(p.upn)}`;
        if (!q(s, office).length) missing.push(`${p.upn}: no office activity`);
        const h = dir.hosts.get(short(p.host));
        if (!h) { missing.push(`${p.upn}: no host`); continue; }
        if (h.os === "Appliance") continue;
        tally(s, "people with a host");
        if (!q(s, `DeviceLogonEvents | where AccountName =~ ${kq(p.name)} and DeviceName =~ ${kq(h.name)}`).length) missing.push(`${p.upn}: no DeviceLogonEvents on ${h.name}`);
        const logon = h.os.startsWith("Windows")
          ? `SecurityEvent | where TargetUserName =~ ${kq(p.name)} and Computer startswith ${kq(h.name)}`
          : `Syslog | where Computer =~ ${kq(h.name)} and SyslogMessage has ${kq(p.name)}`;
        if (!q(s, logon).length) missing.push(`${p.upn}: no logon rows on ${h.name} (${h.os})`);
      }
      expect(missing.slice(0, 30)).toEqual([]);
    });

    it("every host answers: inventory, processes, connections, logons", () => {
      const missing: string[] = [];
      for (const e of s.events) if (e.hostname && isOwnHost(e.hostname, domain, domain) && !dir.hosts.has(short(e.hostname))) missing.push(`not in the directory: ${e.hostname}`);
      for (const h of dir.hosts.values()) {
        tally(s, "hosts");
        const inv = q(s, `DeviceInfo | where DeviceName =~ ${kq(h.name)}`);
        if (inv.length !== 1) missing.push(`${h.name}: DeviceInfo rows ${inv.length}`);
        if (h.os === "Appliance") {
          if (!q(s, `Syslog | where Computer =~ ${kq(h.name)}`).length) missing.push(`${h.name}: no Syslog`);
          continue;
        }
        for (const t of ["DeviceProcessEvents", "DeviceNetworkEvents"]) if (!q(s, `${t} | where DeviceName =~ ${kq(h.name)}`).length) missing.push(`${h.name}: no ${t}`);
        if (h.users.length && !q(s, `DeviceLogonEvents | where DeviceName =~ ${kq(h.name)}`).length) missing.push(`${h.name}: no DeviceLogonEvents`);
      }
      expect(missing.slice(0, 30)).toEqual([]);
    });

    it("every feed IP answers search, and its owner agrees", () => {
      const problems: string[] = [];
      const ips = new Set(s.events.flatMap(e => [e.src_ip, e.dst_ip]).filter((x): x is string => !!x && IPV4.test(x)));
      for (const ip of ips) {
        tally(s, "ips");
        if (!q(s, `search ${kq(ip)} | take 1`).length) problems.push(`${ip}: search finds nothing`);
      }
      const inventory = new Map<string, string>(s.ws.tables.DeviceNetworkInfo.rows.map(r => [short(String(r.DeviceName)), JSON.stringify(r.IPAddresses)]));
      for (const e of s.events) {
        if (!e.hostname || !e.src_ip || !PRIVATE.test(e.src_ip) || !["edr", "sysmon", "firewall", "proxy", "dns"].includes(e.source)) continue;
        const h = dir.hosts.get(short(e.hostname));
        if (!h) continue;
        if (!inventory.get(h.key)?.includes(`"${e.src_ip}"`)) problems.push(`${e.src_ip}: not an address of ${h.name} in DeviceNetworkInfo`);
        if (h.ip !== e.src_ip) tally(s, "feed events printing a second IP for their host");
      }
      for (const h of dir.hosts.values()) if (h.otherIps.length) tally(s, "hosts with more than one IP in the feed");
      const owners = new Map<string, string[]>();
      for (const h of dir.hosts.values()) for (const ip of [h.ip, ...h.otherIps]) owners.set(ip, [...(owners.get(ip) ?? []), h.name]);
      for (const [ip, hs] of owners) if (hs.length > 1) tally(s, `IPs shared by two hosts in the feed`);
      void ips;
      expect(problems.slice(0, 20)).toEqual([]);
    });

    it("every feed event is a row, and the row states the event's user, host, IP and time", () => {
      const problems: string[] = [];
      for (const e of s.events) {
        tally(s, "events");
        const rows = s.ws.eventRows[e.id];
        if (!rows?.length) { problems.push(`${e.id} ${e.source}/${e.vendor}: no row`); continue; }
        const { table, row } = rows[0];
        const text = low(JSON.stringify(row));
        const t = Date.parse(String(row.TimeGenerated));
        if (t !== Date.parse(e.ts)) problems.push(`${e.id} ${table}: time ${String(row.TimeGenerated)} vs ${e.ts}`);
        if (/"feed":"|\b(user|host|ip)=/.test(JSON.stringify(row))) tally(s, "events with a value held in a note, not its own column");
        const cols = identityColumns(table);
        const user = (e.user_email ?? e.user?.email)?.toLowerCase();
        const local = user?.split("@")[0];
        if (local) {
          if (text.includes(local) || text.includes(local.replace(/\./g, ""))) tally(s, "events with user matched");
          else if (table === "SecurityAlert" || cols?.user) problems.push(`${e.id} ${table}: user ${user}`);
          else tally(s, `user not stated: table has no user column (${table})`);
        }
        if (e.hostname) {
          if (text.includes(short(e.hostname))) tally(s, "events with host matched");
          else if (table === "SecurityAlert" || cols?.host) problems.push(`${e.id} ${table}: host ${e.hostname}`);
          else tally(s, `host not stated: table has no host column (${table})`);
        }
        for (const ip of [e.src_ip, e.dst_ip]) {
          if (!ip) continue;
          if (text.includes(ip)) tally(s, "events with IP matched");
          else if (table === "SecurityAlert" || cols?.ip) problems.push(`${e.id} ${table}: IP ${ip}`);
          else tally(s, `IP not stated: table has no IP column (${table})`);
        }
      }
      expect(problems.slice(0, 30)).toEqual([]);
    });

    it("one truth: identity fields agree across tables, and every name is known", () => {
      const problems = new Set<string>();
      const people = new Map<string, KqlRow>(s.ws.tables.IdentityInfo.rows.map(r => [low(r.AccountUPN), r]));
      const devices = new Map<string, KqlRow>(s.ws.tables.DeviceInfo.rows.map(r => [short(String(r.DeviceName)), r]));
      const feedRows = new Set(Object.values(s.ws.eventRows).flat().map(x => x.row));
      const same = (what: string, a: unknown, b: unknown) => { if (a !== undefined && b !== undefined && a !== b) problems.add(`${what}: ${String(a)} vs ${String(b)}`); };
      const external = (u: string) => !ownDomain(u);

      for (const r of s.ws.tables.SigninLogs.rows) {
        const p = people.get(low(r.UserPrincipalName));
        if (!p) { if (!external(String(r.UserPrincipalName))) problems.add(`unknown UPN ${String(r.UserPrincipalName)}`); continue; }
        same(`${String(p.AccountUPN)} object id`, r.UserId, p.AccountObjectId);
        same(`${String(p.AccountUPN)} display`, r.UserDisplayName, p.AccountDisplayName);
      }
      for (const t of ["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceLogonEvents", "DeviceRegistryEvents", "DeviceEvents"]) {
        for (const r of s.ws.tables[t].rows) {
          const d = devices.get(short(String(r.DeviceName)));
          if (!d) { problems.add(`unknown device ${String(r.DeviceName)} in ${t}`); continue; }
          same(`${String(r.DeviceName)} DeviceId in ${t}`, r.DeviceId, d.DeviceId);
          for (const c of ["AccountUpn", "InitiatingProcessAccountUpn"]) {
            const u = r[c];
            if (typeof u !== "string" || !u.includes("@") || external(u)) continue;
            if (!people.has(u.toLowerCase())) problems.add(`unknown ${c} ${u} in ${t}`);
          }
          if (typeof r.AccountSid === "string" && /^S-1-5-21/.test(r.AccountSid)) {
            const p = people.get(`${low(r.AccountName)}@${domain}`);
            if (feedRows.has(r) && p && r.AccountSid !== p.AccountSID) tally(s, "feed Device rows printing another SID");
            else same(`${String(r.AccountName)} SID`, r.AccountSid, p?.AccountSID);
          }
        }
      }
      for (const r of s.ws.tables.SecurityEvent.rows) {
        if (typeof r.TargetUserSid !== "string" || !/^S-1-5-21/.test(r.TargetUserSid)) continue;
        const p = people.get(`${low(r.TargetUserName)}@${domain}`);
        if (feedRows.has(r) && (!p || r.TargetUserSid !== p.AccountSID)) tally(s, "feed SecurityEvent rows printing another account form or SID");
        else same(`${String(r.TargetUserName)} SecurityEvent SID`, r.TargetUserSid, p?.AccountSID);
      }
      // One IP per host, one home for each person, on background rows.
      for (const r of s.ws.tables.DeviceNetworkEvents.rows) {
        if (feedRows.has(r)) continue;
        same(`${String(r.DeviceName)} LocalIP`, r.LocalIP, dir.hosts.get(short(String(r.DeviceName)))?.ip);
      }
      const egress = String(s.ws.tables.DeviceInfo.rows[0]?.PublicIP);
      for (const r of s.ws.tables.SigninLogs.rows) {
        if (feedRows.has(r)) continue;
        const u = dir.people.get(low(r.UserPrincipalName));
        same(`${u?.upn} sign-in address`, r.IPAddress, egress);
        same(`${u?.upn} sign-in device`, (r.DeviceDetail as { displayName?: string }).displayName, dir.hosts.get(short(u?.host ?? ""))?.name);
        same(`${u?.upn} home location`, r.Location, s.ws.tables.SigninLogs.rows.filter(x => !feedRows.has(x))[0]?.Location);
      }
      for (const r of s.ws.tables.OktaV2_CL.rows) {
        if (feedRows.has(r)) continue;
        same(`${String(r.OriginalActorAlternateId)} sign-in address`, r.SrcIpAddr, egress);
      }
      for (const r of s.ws.tables.OfficeActivity.rows) if (!feedRows.has(r)) same(`${String(r.UserId)} office address`, String(r.ClientIP).split(":")[0], egress);
      for (const r of s.ws.tables.SecurityEvent.rows) {
        if (feedRows.has(r)) continue;
        const u = dir.people.get(`${low(r.TargetUserName)}@${domain}`);
        same(`${u?.upn} logon host`, short(String(r.Computer)), short(u?.host ?? ""));
      }
      // Department: a product that states one agrees with the inventory.
      for (const r of s.ws.tables.CommonSecurityLog.rows) {
        if (r.DeviceVendor !== "Zscaler" || !feedRows.has(r) || !r.DeviceCustomString1) continue;
        const p = people.get(low(r.SourceUserName));
        if (p && p.Department !== r.DeviceCustomString1) tally(s, "feed records stating another department than the person's first");
      }
      // Other tables that name a user.
      for (const [t, c] of [["OfficeActivity", "UserId"], ["OktaV2_CL", "OriginalActorAlternateId"], ["EmailEvents", "RecipientEmailAddress"], ["UrlClickEvents", "AccountUpn"], ["GoogleWorkspaceReports", "ActorEmail"], ["AlertEvidence", "AccountUpn"]] as const) {
        for (const r of s.ws.tables[t].rows) {
          const u = r[c];
          if (typeof u === "string" && u.includes("@") && !external(u) && !people.has(u.toLowerCase())) problems.add(`unknown ${c} ${u} in ${t}`);
        }
      }
      for (const [t, table] of Object.entries(s.ws.tables)) {
        if (!table.columns.some(c => c.name === "DeviceName")) continue;
        for (const r of table.rows) if (typeof r.DeviceName === "string" && r.DeviceName && !devices.has(short(r.DeviceName))) problems.add(`unknown DeviceName ${r.DeviceName} in ${t}`);
      }
      const joined = q(s, `DeviceProcessEvents | join kind=leftouter (DeviceInfo | project DeviceId, OSPlatform) on DeviceId | where isempty(OSPlatform) | count`);
      if (Number(joined[0]?.Count) !== 0) problems.add(`join lost ${String(joined[0]?.Count)} rows`);
      const clock = Date.parse(s.ws.now);
      for (const [t, table] of Object.entries(s.ws.tables)) for (const r of table.rows) if (Date.parse(String(r.TimeGenerated)) > clock) problems.add(`${t} row after the clock: ${String(r.TimeGenerated)}`);
      expect([...problems].slice(0, 30)).toEqual([]);
    });

    it("the baseline hides nothing and adds nothing", () => {
      const bare = buildWorkspace(s.events, { ...s.opts, baseline: false });
      expect(JSON.stringify(s.ws.incidents)).toBe(JSON.stringify(bare.incidents));
      expect(JSON.stringify(s.ws.alerts)).toBe(JSON.stringify(bare.alerts));
      expect(bare.baselineRows).toBe(0);

      const feedRows = new Set(Object.values(s.ws.eventRows).flat().map(x => x.row));
      const baseline = Object.entries(s.ws.tables).flatMap(([t, tb]) => tb.rows.filter(r => !feedRows.has(r) && t !== "SecurityAlert" && t !== "SecurityIncident" && t !== "GraphSecurityAlerts_CL").map(r => [t, r] as const));
      expect(baseline.length).toBe(s.ws.baselineRows);
      const attackers = new Set<string>();
      const domains = new Set<string>();
      const ABUSED_SERVICES = /(^|\.)(microsoft\.com|microsoftonline\.com|live\.com|office\.com|google\.com)$/i;
      const victims = new Set<string>();
      for (const e of s.events) {
        if (!isAttack(s.answers.get(e.id))) continue;
        for (const ip of [e.src_ip, e.dst_ip]) if (ip && !PRIVATE.test(ip)) attackers.add(ip);
        const d = e.network?.domain ?? e.dns?.query;
        // A real sign-in service an attack sends its victim to (device-code phishing's microsoft.com/devicelogin) is
        // everyone's everyday traffic too, not the attacker's own infrastructure.
        if (d && !d.endsWith(domain) && !ABUSED_SERVICES.test(d)) domains.add(d.toLowerCase());
        const u = (e.user_email ?? e.user?.email)?.toLowerCase();
        if (u) victims.add(u);
      }
      const egress = new Set(s.ws.tables.DeviceInfo.rows.map(r => String(r.PublicIP)));
      const text = baseline.map(([, r]) => JSON.stringify(r));
      const blob = text.join("\n").toLowerCase();
      const problems: string[] = [];
      for (const ip of attackers) if (!egress.has(ip) && blob.includes(ip)) problems.push(`attacker IP ${ip}`);
      for (const d of domains) if (blob.includes(d)) problems.push(`attacker domain ${d}`);
      if (s.opts.identity) if (blob.includes("nexacorp")) problems.push("template name in a named organization");

      // The same shape for everyone: a compromised user is no different from a quiet one.
      const shape = new Map<string, Map<string, number>>();
      for (const [t, r] of baseline) {
        for (const c of ["UserPrincipalName", "OriginalActorAlternateId", "UserId", "ActorEmail"]) {
          const u = low(r[c]);
          if (!u.includes("@")) continue;
          const m = shape.get(u) ?? new Map<string, number>();
          m.set(t, (m.get(t) ?? 0) + 1);
          shape.set(u, m);
        }
      }
      const mean = (who: string[], t: string) => who.reduce((a, u) => a + (shape.get(u)?.get(t) ?? 0), 0) / Math.max(1, who.length);
      const all = [...shape.keys()].filter(u => !dir.people.get(u)?.service);
      const hit = all.filter(u => victims.has(u)), quiet = all.filter(u => !victims.has(u));
      if (hit.length && quiet.length) {
        for (const t of ["SigninLogs", "OktaV2_CL", "OfficeActivity", "GoogleWorkspaceReports"]) {
          const a = mean(hit, t), b = mean(quiet, t);
          if (a + b > 0 && Math.abs(a - b) / Math.max(a, b) > 0.15) problems.push(`${t}: victims ${a.toFixed(1)} rows, quiet users ${b.toFixed(1)}`);
        }
      }
      const tablesOf = new Set(baseline.map(([t]) => t));
      if (okta && tablesOf.has("SigninLogs")) problems.push("an Okta shop with Entra sign-ins");
      if (!okta && tablesOf.has("OktaV2_CL")) problems.push("an Entra shop with Okta sign-ins");
      if (google && tablesOf.has("OfficeActivity")) problems.push("a Google shop with Office activity");
      if (!google && tablesOf.has("GoogleWorkspaceReports")) problems.push("a Microsoft shop with Google activity");
      const apps = new Map<string, Set<string>>(), hosts = new Map<string, Set<string>>();
      for (const [t, r] of baseline) {
        if (t === "SigninLogs") { const m = apps.get(low(r.UserPrincipalName)) ?? new Set(); m.add(String(r.AppDisplayName)); apps.set(low(r.UserPrincipalName), m); }
        if (t === "DeviceLogonEvents") { const m = hosts.get(low(r.AccountName)) ?? new Set(); m.add(String(r.DeviceName)); hosts.set(low(r.AccountName), m); }
      }
      for (const [u, m] of hosts) if (m.size !== 1) problems.push(`${u}: ${m.size} hosts in the background`);
      const size = (who: string[]) => who.reduce((a, u) => a + (apps.get(u)?.size ?? 0), 0) / Math.max(1, who.length);
      if (hit.length && quiet.length && apps.size && Math.abs(size(hit) - size(quiet)) > 0.8) problems.push(`apps: victims ${size(hit)}, quiet ${size(quiet)}`);

      // Rules run on feed rows. Who would see background rows is an analyst opening a rule's query.
      const only = Object.fromEntries(Object.entries(s.ws.tables).map(([n, t]) => [n, { ...t, rows: t.rows.filter(r => !feedRows.has(r) && n !== "SecurityAlert" && n !== "SecurityIncident") }]));
      for (const rule of s.ws.rules) {
        // As the scheduler runs it: over the rule's lookback.
        const span = /(\d+) minutes/.exec(rule.lookback) ? Number(/(\d+)/.exec(rule.lookback)![1]) * 60_000 : Number(/(\d+)/.exec(rule.lookback)?.[1] ?? 1) * 3_600_000;
        const to = new Date(s.ws.now);
        const r = runKql(rule.query, { tables: only, now: to, timeRange: { from: new Date(to.getTime() - span), to } });
        if (r.ok && r.rows.length) { tally(s, "rule queries matching background rows"); ruleHits.add(rule.id); }
      }
      expect(problems.slice(0, 20)).toEqual([]);
    });

    it("external addresses in the baseline are documentation addresses or the office egress", () => {
      const feedRows = new Set(Object.values(s.ws.eventRows).flat().map(x => x.row));
      const egress = String(s.ws.tables.DeviceInfo.rows[0]?.PublicIP);
      const seen = new Set<string>();
      for (const t of ["SigninLogs", "OktaV2_CL", "OfficeActivity", "CommonSecurityLog", "DeviceNetworkEvents", "AWSCloudTrail", "AzureActivity", "GoogleWorkspaceReports", "DnsEvents"]) {
        for (const r of s.ws.tables[t].rows) {
          if (feedRows.has(r)) continue;
          for (const c of ["IPAddress", "SrcIpAddr", "ClientIP", "DestinationIP", "RemoteIP", "SourceIpAddress", "CallerIpAddress"]) {
            const v = r[c];
            if (typeof v === "string" && IPV4.test(v.split(":")[0]) && !PRIVATE.test(v) && !DOC_IP.test(v) && v.split(":")[0] !== egress) seen.add(`${t}.${c}=${v}`);
          }
        }
      }
      if (egress && !DOC_IP.test(egress)) tally(s, "sessions whose office egress is not a documentation address");
      expect([...seen]).toEqual([]);
    });

    it("every Microsoft detection is exactly one Graph alert, equal in the feed record, SecurityAlert and the Graph table", () => {
      const problems: string[] = [];
      const norm = (l: { kind: string; name: string }[]) => l.map(e => `${e.kind}:${e.name}`.toLowerCase()).sort().join("|");
      const fromEvidence = (ev: Record<string, unknown>[]) => ev.flatMap(e => {
        const kind = String(e["@odata.type"]).split(".").pop();
        const account = e.userAccount as { userPrincipalName?: string; accountName?: string } | undefined;
        if (kind === "deviceEvidence") return [{ kind: "host", name: String(e.hostName ?? e.deviceDnsName) }];
        if (kind === "userEvidence") return [{ kind: "account", name: String(account?.userPrincipalName ?? account?.accountName).split("@")[0] }];
        if (kind === "ipEvidence") return [{ kind: "ip", name: String(e.ipAddress) }];
        if (kind === "urlEvidence") return [{ kind: "url", name: String(e.url) }];
        if (kind === "mailboxEvidence") return [{ kind: "mailbox", name: String(e.primaryAddress) }];
        if (kind === "fileEvidence") return [{ kind: "file", name: String((e.fileDetails as { fileName?: string })?.fileName) }];
        return [];
      });
      const fromColumn = (col: unknown) => (JSON.parse(String(col)) as Record<string, unknown>[]).flatMap(e => {
        const name = e.HostName ?? e.Address ?? e.Url ?? e.MailboxPrimaryAddress ?? e.Name;
        return ["host", "account", "ip", "url", "mailbox", "file"].includes(String(e.Type)) ? [{ kind: String(e.Type), name: String(name) }] : [];
      });
      for (const e of s.events) {
        const log = graphAlertFor(e, s.company, STACK, s.opts.identity);
        if (!log) continue;
        tally(s, "Microsoft detections");
        const g = (log.record as { data: Record<string, Record<string, unknown>> }).data["ms-graph"];
        const id = String(g.id);
        const rows = q(s, `GraphSecurityAlerts_CL | where id == ${kq(id)}`);
        const alerts = q(s, `SecurityAlert | where VendorOriginalId == ${kq(id)}`);
        if (rows.length !== 1) { problems.push(`${id}: Graph table rows ${rows.length}`); continue; }
        if (alerts.length !== 1) { problems.push(`${id}: SecurityAlert rows ${alerts.length}`); continue; }
        const [row] = rows, [alert] = alerts;
        const title = plain(String(g.title));
        if (plain(String(row.title)) !== title || alert.AlertName !== title) problems.push(`${id}: title ${String(g.title)} / ${String(row.title)} / ${String(alert.AlertName)}`);
        if (low(row.severity) !== low(g.severity) || low(alert.AlertSeverity) !== low(g.severity)) problems.push(`${id}: severity ${String(g.severity)} / ${String(row.severity)} / ${String(alert.AlertSeverity)}`);
        const want = norm(fromEvidence(g.evidence as unknown as Record<string, unknown>[]));
        const table = norm(fromEvidence(row.evidence as Record<string, unknown>[]));
        const col = norm(fromColumn(alert.Entities));
        if (want !== table || want !== col) problems.push(`${id}: entities ${want} / ${table} / ${col}`);
        if (alert.AlertLink !== g.alertWebUrl) problems.push(`${id}: AlertLink`);
        const sa = s.ws.alerts.find(a => a.graph?.id === id);
        if (!sa) problems.push(`${id}: alert details carry no Graph fields`);
        if (e.is_detection && e.source === "edr" && s.ws.eventRows[e.id]?.[0]?.table !== "AlertEvidence" && !s.ws.eventRows[e.id]?.some(r => r.table.startsWith("Device"))) problems.push(`${id}: Defender row lost`);
      }
      expect(s.ws.tables.GraphSecurityAlerts_CL.rows.length).toBe(counts[s.key.split("/")[0]] ? s.ws.alerts.filter(a => a.graph).length : 0);
      expect(problems.slice(0, 20)).toEqual([]);
    });

    it("hunting, rule and insight queries still run", () => {
      const problems: string[] = [];
      const noRange = { tables: s.ws.tables, now: new Date(s.ws.now) };
      for (const x of [...s.ws.hunting, ...s.ws.rules]) {
        const r = runKql(x.query, noRange);
        if (!r.ok) problems.push(`${x.id}: ${r.error.message}`);
      }
      for (const inc of s.ws.incidents.slice(0, 3)) incidentInsights(s.ws, inc);
      for (const id of Object.keys(s.ws.entities).slice(0, 6)) entityInsights(s.ws, id);
      expect(problems.slice(0, 20)).toEqual([]);
    });

    it("a rebuild gives the same rows, and the clock only reveals more", () => {
      const again = buildWorkspace(s.events, s.opts);
      expect(again.baselineRows).toBe(s.ws.baselineRows);
      const texts = (ws: SentinelWorkspaceBuild) => JSON.stringify(ws.tables.SigninLogs.rows.concat(ws.tables.OktaV2_CL.rows).slice(0, 200));
      expect(texts(again)).toBe(texts(s.ws));
      const earlier = buildWorkspace(s.events.slice(0, Math.ceil(s.events.length / 2)), s.opts);
      for (const [upn, p] of earlier.directory!.people) {
        const later = dir.people.get(upn);
        if (later && later.host !== p.host) tally(s, "people whose usual host moved when the feed first placed them");
      }
      const clock = Date.parse(earlier.now);
      for (const t of Object.values(earlier.tables)) for (const r of t.rows) expect(Date.parse(String(r.TimeGenerated))).toBeLessThanOrEqual(clock);
      expect(new Set(earlier.incidents.map(i => i.number)).size).toBe(earlier.incidents.length);
    });
  });
}

describe("build time", () => {
  it("a full first build and a rebuild", () => {
    const s = open("quantumbank", "hard", "perf");
    // The best of three: the suite runs on busy workers, and a stall there says nothing about the code.
    let first = Infinity, again = Infinity;
    for (const run of [1, 2, 3]) {
      const fresh = { ...s.opts, orgName: `perf-check-${run}` };
      const t0 = performance.now();
      buildWorkspace(s.events, fresh);
      first = Math.min(first, performance.now() - t0);
      const t1 = performance.now();
      buildWorkspace(s.events, fresh);
      again = Math.min(again, performance.now() - t1);
    }
    if (process.env.CORR_OUT) writeFileSync(`${process.env.CORR_OUT}.perf`, JSON.stringify({ first, again, rows: s.ws.baselineRows }));
    expect(first).toBeLessThan(300); // about 150 ms in a browser-class run; CI headroom
    expect(again).toBeLessThan(60);
  });
});
