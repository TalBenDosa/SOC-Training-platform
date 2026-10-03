// TECHNICAL INTEGRITY GATE — every log that can reach a trainee's screen, across all
// companies × default and chosen vendor stacks, single-user dashboard and team mode.
// One test per requirement (Tal, 2026-10-02):
//   1 one IP per computer, never one IP for two computers
//   2 hash verdicts match the scenario (payload malicious, system binaries / noise clean)
//   3 no information leak (no conclusion on the row, the panel or the record)
//   4 every row has a general description, and the record holds the entities it names
//   5 product behaviour — label = rendering product, schema-valid native record
//   6 valid JSON, convertible to a raw view, no "undefined" / "NaN" / "[object Object]"
//   7 no repeated log inside a story / a team session
//   8 attacks land on different employees (no single victim)
//   9 every attack is backed by real, rendered evidence
//  10 the team report measures escalations against the real incidents
import { describe, it, expect, vi } from "vitest";
import { storiesForCompany, instantiateStory, type AttackStory } from "@/app/(app)/dashboard/attackStories";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { enrichEvent } from "@/app/(app)/dashboard/liveEventEnrich";
import { toRawLog } from "@/app/(app)/dashboard/rawLogFormat";
import { buildTeamTimeline, teamStoryPool, teamStoryFilter } from "@/lib/team/buildTimeline";
import { PLATFORM_CHOICES, type TeamEnv } from "@/lib/team/environment";
import { teamLoad } from "@/lib/team/load";
import { computeReport } from "@/lib/team/report/computeReport";
import { applyStack, fitsStack, storyFitsStack, storyHonoursLocks, nativeView, authoredOf, NATIVE_SOURCES } from "@/lib/logs/native";
import { categoryOf, PRODUCT_LABEL, type Stack } from "@/lib/logs/native/stack";
import { validateNative } from "@/lib/logs/native/validate";
import { describeEventForRow } from "@/lib/sim/describeEvent";
import { assessIoc } from "@/lib/edr/iocIntel";
import { storyIocTruth } from "@/lib/sim/storyTruth";
import { normalizeHostIps } from "@/lib/sim/hostIdentity";
import { parseTenant, tenantIdentity, TENANT_TEMPLATE, type Tenant } from "@/lib/team/tenant";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { Ev, RosterMember } from "@/lib/team/types";

// ── dataset ─────────────────────────────────────────────────────────────────────
// Each company's noise pool exactly as the dashboard builds it (one IP per host).
const COMPANIES: [string, TelemetryEvent[]][] = ([
  ["nexacorp", BENIGN_EVENTS], ["medcore", COMPANY_EVENTS.medcore], ["rocketstack", COMPANY_EVENTS.rocketstack],
  ["globallogis", COMPANY_EVENTS.globallogis], ["quantumbank", COMPANY_EVENTS.quantumbank],
] as [string, TelemetryEvent[]][]).map(([c, pool]) => [c, normalizeHostIps(pool)]);
const STACKS: Stack[] = [
  {},
  { edr: "crowdstrike", firewall: "fortigate", vpn: "anyconnect", idp: "okta", collab: "google_workspace", dns: "infoblox" },
  { edr: "sentinelone", firewall: "checkpoint", vpn: "zscaler_zpa", email_security: "proofpoint" },
];
// An attack log: an explicit tp/escalate verdict, or — story events often carry none —
// an ATT&CK technique on a non-baseline event (decoys carry fp/benign explicitly).
const TP = (e: TelemetryEvent) => e.expected_verdict ? e.expected_verdict === "tp" || e.expected_verdict === "escalate" : !!e.mitre_technique && !e.is_baseline;
// Inside a story every event is part of the attack unless it is explicitly a baseline / benign / decoy.
const STORY_ATTACK = (e: TelemetryEvent) => !e.is_baseline && !["benign", "fp", "false_positive"].includes(String(e.expected_verdict ?? ""));
const edrFor = (company: string, stack: Stack) => (stack.edr && PRODUCT_LABEL[stack.edr]) || COMPANY_PROFILES.find(c => c.id === company)?.architecture.edr;
const label = (company: string, stack: Stack, tenant?: Tenant, story?: string) => `${tenant ? `org:${tenant.domain}` : company}${Object.keys(stack).length ? " " + JSON.stringify(stack) : ""}${story ? ` pinned:${story}` : ""}`;

interface StoryRun { company: string; stack: Stack; story: AttackStory; events: TelemetryEvent[] }
let storyRuns: StoryRun[] | null = null;
function stories(): StoryRun[] {
  if (storyRuns) return storyRuns;
  storyRuns = [];
  for (const [company, pool] of COMPANIES) for (const stack of STACKS) {
    const chosen = Object.keys(stack).length > 0;
    const seen = new Set<string>();
    for (const diff of ["easy", "medium", "hard"] as const) for (const s of storiesForCompany(company, diff)) {
      if (seen.has(s.id)) continue; seen.add(s.id);
      const raw = instantiateStory(s, pool, edrFor(company, stack), company).events ?? [];
      const evs = raw.map(e => applyStack(e, company, stack));
      if (!(chosen ? storyFitsStack(evs, company, stack) : storyHonoursLocks(evs, company))) continue;
      storyRuns.push({ company, stack, story: s, events: evs });
    }
  }
  return storyRuns;
}
interface TeamRun { company: string; stack: Stack; feed: TelemetryEvent[]; answers: Record<string, unknown>[]; tenant?: Tenant; story?: string }
let teamRuns: TeamRun[] | null = null;
function teams(): TeamRun[] {
  if (teamRuns) return teamRuns;
  teamRuns = [];
  const roster = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
  for (const [company] of COMPANIES) for (const stack of STACKS.slice(0, 2)) for (const diff of ["medium", "hard"] as const) {
    const tl = buildTeamTimeline(company, diff, `gate-${company}-${diff}`, null, teamLoad(diff, roster), stack);
    const f = tl.filter(t => t.channel === "feed");
    teamRuns.push({ company, stack, feed: f.map(t => t.body as unknown as TelemetryEvent), answers: f.map(t => (t.answer ?? {}) as Record<string, unknown>) });
  }
  // Exercises run as an instructor-named organization (the template environment, renamed).
  for (const [name, stack] of [["acme-labs", {}], ["northwind.io", STACKS[1]]] as [string, Stack][]) for (const diff of ["medium", "hard"] as const) {
    const tenant = parseTenant(name) as Tenant;
    const tl = buildTeamTimeline(TENANT_TEMPLATE, diff, `gate-${name}-${diff}`, null, teamLoad(diff, roster), stack, tenant);
    const f = tl.filter(t => t.channel === "feed");
    teamRuns.push({ company: TENANT_TEMPLATE, stack, tenant, feed: f.map(t => t.body as unknown as TelemetryEvent), answers: f.map(t => (t.answer ?? {}) as Record<string, unknown>) });
  }
  // The named organization's whole arsenal: every story its environment (all platforms, each
  // industry) can draw, on its template products and on chosen ones — each pinned once, so
  // stories written for MedCore / RocketStack / GlobalLogis / QuantumBank and the borrowed
  // AWS / PAM noise all pass every check as the organization's own.
  const ALL = PLATFORM_CHOICES.map(p => p.id);
  const ORG_ENVS: [TeamEnv, Stack][] = [
    [{ platforms: ALL, industry: "general" }, {}],
    [{ platforms: ALL, industry: "healthcare" }, {}],
    [{ platforms: ALL, industry: "logistics" }, {}],
    [{ platforms: ALL, industry: "finance" }, { idp: "okta" }],
    [{ platforms: ALL, industry: "general" }, { idp: "okta", collab: "google_workspace" }],
    [{ platforms: ALL, industry: "general" }, { vpn: "fortigate_sslvpn", firewall: "fortigate" }],
  ];
  const tierDiff = { foundation: "easy", core: "medium", advanced: "hard" } as const;
  const tenant = parseTenant("contoso-health.io") as Tenant;
  for (const [env, stack] of ORG_ENVS) {
    const fits = teamStoryFilter(TENANT_TEMPLATE, stack, env);
    const covered = new Set<string>();
    for (const diff of ["easy", "medium", "hard"] as const) for (const s of teamStoryPool(TENANT_TEMPLATE, diff, env, stack)) {
      if (covered.has(s.id) || tierDiff[s.complexity] !== diff || !fits(s)) continue;
      covered.add(s.id);
      const tl = buildTeamTimeline(TENANT_TEMPLATE, diff, `arsenal-${s.id}`, s.id, teamLoad(diff, roster.slice(0, 3)), stack, tenant, env);
      const f = tl.filter(t => t.channel === "feed");
      teamRuns.push({ company: TENANT_TEMPLATE, stack, tenant, story: s.id, feed: f.map(t => t.body as unknown as TelemetryEvent), answers: f.map(t => (t.answer ?? {}) as Record<string, unknown>) });
    }
  }
  return teamRuns;
}
const report = (cat: string, problems: Set<string>) => expect([...problems].slice(0, 25), cat).toEqual([]);
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
const HOST_SOURCES = new Set(["edr", "sysmon", "av", "windows_security", "linux_audit"]);
const OUTBOUND_SOURCES = new Set(["firewall", "proxy", "dns"]);

// ── 1. IP identity ──────────────────────────────────────────────────────────────
function ipProblems(events: TelemetryEvent[], where: string, problems: Set<string>) {
  const ipsOf = new Map<string, Set<string>>(), hostsOf = new Map<string, Set<string>>();
  for (const e of events) {
    if (!e.hostname || !e.src_ip || !PRIVATE.test(e.src_ip)) continue;
    const inbound = (e.network as { direction?: string } | undefined)?.direction === "inbound" || /inbound/i.test(String(e.raw?.["network.direction"] ?? ""));
    if (inbound) continue;
    if (!HOST_SOURCES.has(e.source) && !OUTBOUND_SOURCES.has(e.source)) continue;
    if (e.event_type === "net_connection" && HOST_SOURCES.has(e.source) && (e.network as { direction?: string } | undefined)?.direction !== "outbound") continue;
    const h = e.hostname.toUpperCase();
    (ipsOf.get(h) ?? ipsOf.set(h, new Set()).get(h)!).add(e.src_ip);
    (hostsOf.get(e.src_ip) ?? hostsOf.set(e.src_ip, new Set()).get(e.src_ip)!).add(h);
  }
  for (const [h, ips] of ipsOf) if (ips.size > 1) problems.add(`${where}: ${h} has ${ips.size} IPs (${[...ips].join(", ")})`);
  for (const [ip, hs] of hostsOf) if (hs.size > 1) problems.add(`${where}: ${ip} used by ${[...hs].join(", ")}`);
}

// ── shared per-event checks (2-6) ───────────────────────────────────────────────
const CONCLUSION = /\b(attacker|adversary|malicious|compromis\w*|exfiltrat\w*|lateral movement|persistence|command[- ]and[- ]control|beacon\w*|backdoor|ransomware|stolen|impersonat\w*|infostealer|credential theft|C2)\b/i;
const BAD_VALUE = /^(undefined|NaN|Infinity|\[object Object\]|Invalid Date)$/;
const SHA256 = /\b[a-f0-9]{64}\b/gi;
function walk(v: unknown, path: string, out: string[]) {
  if (typeof v === "number" && !Number.isFinite(v)) out.push(`${path}=${v}`);
  else if (typeof v === "string") { if (/analystVerdict$/.test(path) && v === "undefined") return;   // SentinelOne's literal default
    if (/(src|dst)intfrole$/.test(path) && v === "undefined") return;   // FortiOS: a tunnel interface (ssl.root) has no role
    if (BAD_VALUE.test(v.trim()) || v.includes("[object Object]") || /\bundefined\b/.test(v) && v.length < 40) out.push(`${path}="${v.slice(0, 40)}"`); }
  else if (v === undefined) out.push(`${path}=undefined`);
  else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${path}[${i}]`, out));
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) walk(x, path ? `${path}.${k}` : k, out);
}

// The gate builds every company × stack and the named organization's whole arsenal once (cached).
describe("technical integrity gate", { timeout: 600_000 }, () => {
  it("1. one IP per computer, never one IP for two computers", () => {
    const p = new Set<string>();
    for (const r of stories()) ipProblems(r.events, `${label(r.company, r.stack)} story:${r.story.id}`, p);
    // The dashboard streams the story INTO the company's noise: one host, one IP across both.
    const poolOf = new Map(COMPANIES);
    for (const r of stories()) if (!Object.keys(r.stack).length) {
      const pool = (poolOf.get(r.company) ?? []).filter(e => fitsStack(e, r.company, {})).map(e => applyStack(e, r.company, {}));
      const hosts = new Set(r.events.map(e => e.hostname?.toUpperCase()).filter(Boolean));
      ipProblems([...r.events, ...pool.filter(e => hosts.has(e.hostname?.toUpperCase()))], `dashboard ${r.company} story:${r.story.id} + noise`, p);
    }
    for (const t of teams()) ipProblems(t.feed, `team ${label(t.company, t.stack, t.tenant, t.story)}`, p);
    report("ip", p);
  });

  it("2. hash verdicts match the scenario", () => {
    const p = new Set<string>();
    for (const r of stories()) {
      // What the trainee's lookup answers: the dashboard passes the shift's story truth table.
      const truth = storyIocTruth(r.events);
      const verdictOf = new Map<string, string>();
      const authoredOn = (e: TelemetryEvent) => [e.file?.sha256, (e.process as { hash?: { sha256?: string } } | undefined)?.hash?.sha256,
        ...Object.entries(e.raw ?? {}).filter(([k, x]) => /sha256/i.test(k) && typeof x === "string").map(([, x]) => String(x))]
        .filter((x): x is string => !!x).map(x => x.toLowerCase());
      // A binary's authored hash travels with the binary: the endpoint story pass shows it on every row that names
      // the binary as a parent / writer (native/sources/_proc-identity threadEndpointStory) — still the story's payload.
      const storyAuthored = new Set(r.events.flatMap(authoredOn));
      for (const e of r.events) {
        const v = nativeView(e, r.company, r.stack);
        // A record's own 64-hex identifiers (Sophos Detections entity "id"s, detection_thumbprint) are ids, not file hashes.
        const text = (v ? JSON.stringify(v.log.record) + (v.log.rawLine ?? "") : JSON.stringify(e.raw ?? {})).replace(/"(id|detection_thumbprint)":"[0-9a-f]{64}/gi, "\"$1\":\"");
        const authored = new Set(authoredOn(e));
        const known = (h: string) => authored.has(h) || storyAuthored.has(h);
        for (const h of new Set((text.match(SHA256) ?? []).map(x => x.toLowerCase()))) {
          const verdict = assessIoc("hash", h, { event: e, truth }).verdict;
          const tag = `${label(r.company, r.stack)} story:${r.story.id} ${authoredOf(e).id}`;
          if (!STORY_ATTACK(e) && verdict === "malicious") p.add(`${tag}: benign log's hash ${h.slice(0, 12)}… looks up malicious`);
          if (STORY_ATTACK(e) && verdict === "malicious" && !known(h)) p.add(`${tag}: rendered-only hash ${h.slice(0, 12)}… (not the payload) looks up malicious`);
          if (authored.has(h)) {
            const prev = verdictOf.get(h);
            if (prev && prev !== verdict && STORY_ATTACK(e)) p.add(`${tag}: hash ${h.slice(0, 12)}… is ${verdict} here but ${prev} elsewhere in the story`);
            verdictOf.set(h, verdict);
          }
        }
        if (STORY_ATTACK(e) && ["edr", "av"].includes(e.source) && (e.is_detection || /detection|alert|quarantine/.test(e.event_type)) && e.file?.sha256 &&
            assessIoc("hash", e.file.sha256, { event: e, truth }).verdict !== "malicious") {
          p.add(`${label(r.company, r.stack)} story:${r.story.id} ${authoredOf(e).id}: detected file's hash does not look up malicious`);
        }
      }
    }
    for (const [company, pool] of COMPANIES) for (const e of pool) {
      if (TP(e)) continue;
      for (const h of [e.file?.sha256].filter((x): x is string => !!x)) {
        if (assessIoc("hash", h, { event: e }).verdict === "malicious") p.add(`${company} noise ${e.id}: hash ${h.slice(0, 12)}… looks up malicious`);
      }
    }
    report("hash", p);
  });

  it("3. no information leak — no conclusion in the row line of an attack log", () => {
    const p = new Set<string>();
    for (const r of stories()) for (const e of r.events) {
      if (!TP(e) || !e.mitre_technique) continue;
      const live = enrichEvent(e, 0);
      const row = describeEventForRow(live).action;
      const panel = live.displayDescription ?? "";
      for (const [where, txt] of [["row", row], ["panel", panel]] as const) {
        const m = txt.match(CONCLUSION);
        if (m) p.add(`${label(r.company, r.stack)} story:${r.story.id} ${authoredOf(e).id}: ${where} says "${m[0]}" — ${txt.slice(0, 90)}`);
      }
    }
    report("leak", p);
  });

  it("3b. no other tenant's identity in a company's rows or records", () => {
    const p = new Set<string>();
    const TENANT: Record<string, RegExp> = {
      nexacorp: /nexacorp|\bNXC-|-NXC-/i, medcore: /medcore/i, rocketstack: /rocketstack/i,
      globallogis: /globallogis|\bSRV-GL-/i, quantumbank: /quantumbank|\bqbank\b|-QB-/i,
    };
    const check = (e: TelemetryEvent, company: string, stack: Stack, where: string) => {
      const v = nativeView(e, company, stack);
      const text = JSON.stringify([e.hostname, e.user_email, e.description, v ? v.log.record : e.raw, v?.log.rawLine]);
      for (const [other, re] of Object.entries(TENANT)) if (other !== company) {
        const m = text.match(re);
        if (m) p.add(`${where} ${authoredOf(e).id}: shows ${other}'s identity "${m[0]}"`);
      }
    };
    for (const r of stories()) for (const e of r.events) check(e, r.company, r.stack, `${label(r.company, r.stack)} story:${r.story.id}`);
    for (const t of teams()) {
      if (!t.tenant) { for (const e of t.feed) check(e, t.company, t.stack, `team ${label(t.company, t.stack)}`); continue; }
      t.feed.forEach((e, i) => {
        const v = nativeView(e, t.company, t.stack, tenantIdentity(t.tenant));
        const text = JSON.stringify([e.hostname, e.user_email, e.description, v ? v.log.record : e.raw, v?.log.rawLine, t.answers[i]]);
        for (const [co, re] of Object.entries(TENANT)) { const m = text.match(re); if (m) p.add(`team ${label(t.company, t.stack, t.tenant, t.story)} ${authoredOf(e).id}: shows ${co}'s identity "${m[0]}"`); }
        for (const mail of text.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) ?? []) {
          const d = mail.split("@")[1].toLowerCase();
          // A mailbox at a demo company's domain inside a named organization's exercise is a leak.
          if (Object.values(TENANT).some(r => r.test(d))) p.add(`team ${label(t.company, t.stack, t.tenant, t.story)}: ${mail}`);
        }
      });
    }
    report("tenant", p);
  });

  it("4. every row has a general description and the record holds the entities it names", () => {
    const p = new Set<string>();
    const check = (e: TelemetryEvent, company: string, stack: Stack, where: string) => {
      const live = enrichEvent(e, 0);
      const row = describeEventForRow(live);
      if (!row.action || row.action.trim().length < 8 || /^(event|log|activity)$/i.test(row.action.trim())) p.add(`${where} ${authoredOf(e).id}: no usable description ("${row.action}")`);
      const v = nativeView(e, company, stack);
      // Legacy rows: the panel shows the core fields (host.name, user.email, source/destination IP —
      // EventFeed ecsCore) above the raw block, so those count as part of the record.
      const legacyCore = [e.hostname, e.user_email, e.src_ip, e.dst_ip, e.process?.user].filter(Boolean).join(" ");
      const text = (v ? JSON.stringify(v.log.record) + (v.log.rawLine ?? "") : `${JSON.stringify(e.raw ?? {})} ${legacyCore}`).toLowerCase();
      const host = e.hostname?.toLowerCase().split(".")[0];
      const sid = v?.log.sourceId;
      // Where the real product does not carry the entity: a DNS server logs the client IP
      // only; a ticket, a SaaS audit record and a firewall (it logs addresses) name no host.
      const serverSide = ["siem", "soar", "dns"].includes(e.source);
      // A domain controller's own Security log (Kerberos tickets, NTLM validation, directory
      // access/changes, lockouts, account/group management, log-cleared) names the DC as Computer
      // and the operation's security principal — never the workstation that triggered it or the
      // human at the keyboard (those events carry no such field). The workstation / launching user
      // live in the correlated host-side logon (4624) instead.
      const WINSEC_DC_KINDS = new Set(["4662", "4768", "4769", "4771", "4776", "5136", "4740", "1102",
        "4720", "4722", "4723", "4724", "4725", "4726", "4738", "4767", "4728", "4729", "4732", "4733", "4756", "4757", "4697"]);
      const winsecDc = sid === "windows_security" && WINSEC_DC_KINDS.has(v?.log.kind ?? "");
      const noHost = serverSide || winsecDc || ["m365", "google_workspace", "entra", "okta", "aws_cloudtrail", "azure_activity", "gcp_audit", "proofpoint", "defender_o365",
        "paloalto", "fortigate", "checkpoint", "cisco_ftd", "cisco_asa", "zscaler_zia", "anyconnect", "globalprotect", "fortigate_sslvpn", "zscaler_zpa", "cloudflare_access"].includes(sid ?? "");
      if (host && !text.includes(host) && !noHost) p.add(`${where} ${authoredOf(e).id}: row host ${e.hostname} missing from the ${v ? v.log.sourceId : "legacy"} record`);
      const user = (e.user_email ?? "").toLowerCase().split("@")[0];
      const asName = user.split(/[._]/).filter(Boolean).join(" ");
      // A service-context process (SYSTEM — a task, PSEXESVC) is logged under that account; a
      // Defender AlertEvidence "Machine" row carries no account; a network event the story
      // authored without a process has no process user to show.
      const systemContext = /system|local service|network service/i.test(e.process?.user ?? "") && /system|s-1-5-18/.test(text);
      // Defender AlertEvidence is a multi-row table (one row per entity) and the feed shows one row.
      const machineEvidence = sid === "mde" && /alertevidence/.test(text);
      const noProcessNet = /net_connection|dns|file_/.test(e.event_type) && !e.process;
      // App-only access (UAL UserType 5 — UserId is the app) and an app-initiated Entra audit
      // carry the application, not the person whose consent was abused.
      const appActor = (sid === "m365" && /"usertype":5\b/.test(text)) || (sid === "entra" && /"initiatedby":\{"app":\{/.test(text) && /"user":null/.test(text));
      // CrowdStrike process events carry the user's SID, not a name (analysts pivot via UserLogon).
      const sidOnly = (sid === "crowdstrike" && /"usersid":"s-1-5-/.test(text))
        // auditd names the account by uid (a successful USER_LOGIN writes id=<uid>; acct= only on failure)
        || (sid === "linux_auditd" && /\b(auid|uid|id)=\d+/.test(text));
      if (user && user.length > 2 && !sidOnly && !systemContext && !machineEvidence && !noProcessNet && !appActor && !winsecDc && sid !== "crowdstrike" && !text.includes(user) && !text.includes(user.replace(/\./g, "")) && !text.includes(asName) && !serverSide) p.add(`${where} ${authoredOf(e).id}: row user ${e.user_email} missing from the ${v ? v.log.sourceId : "legacy"} record`);
      // An IP is part of the record only where the product logs one (a connection, a sign-in, a DNS
      // query) — a Defender process event has no address field, and inventing one would be wrong.
      const netLike = (/net|dns|http|conn|vpn|auth|login|sign|session|url|web|email/i.test(e.event_type) || ["firewall", "proxy", "dns", "vpn", "idp", "okta", "waf"].includes(e.source))
        && !(sid === "sysmon" && /dns/i.test(e.event_type));   // Sysmon EID 22 (DNS query) has no address field
      // A DNS server's debug log names the client, not itself; Okta / Entra see a corporate user's
      // public egress, never the internal address.
      // auditd writes the remote addr, never the server's own address.
      const skipIp = (ip: string) => (e.source === "dns" && ip === e.dst_ip) || (sid === "linux_auditd" && ip === e.dst_ip) || (["okta", "entra"].includes(sid ?? "") && PRIVATE.test(ip)) || appActor;
      for (const ip of [e.src_ip, e.dst_ip]) if (ip && !skipIp(ip) && netLike && ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip) && !text.includes(ip) && v) p.add(`${where} ${authoredOf(e).id}: row IP ${ip} missing from the ${v.log.sourceId} record`);
    };
    for (const r of stories()) for (const e of r.events) {
      check(e, r.company, r.stack, `${label(r.company, r.stack)} story:${r.story.id}`);
      // The pid the EDR console's tree and the panel show is the one the native EDR record prints.
      const v = e.process?.pid && ["edr", "sysmon"].includes(e.source) ? nativeView(e, r.company, r.stack) : null;
      // Only records that print the process's OWN pid (a file / threat record carries an internal id or none).
      const ownPidKind = v && ((v.log.sourceId === "crowdstrike" && v.log.kind === "ProcessRollup2") || (v.log.sourceId === "mde" && v.log.kind === "DeviceProcessEvents")
        || (v.log.sourceId === "sentinelone" && v.log.kind === "Process Creation") || (v.log.sourceId === "sysmon" && v.log.kind === "1"));
      if (v && ownPidKind) {
        const t = JSON.stringify(v.log.record) + (v.log.rawLine ?? "");
        if (!t.includes(String(e.process!.pid))) p.add(`${label(r.company, r.stack)} story:${r.story.id} ${authoredOf(e).id}: pid ${e.process!.pid} not in the ${v.log.sourceId} record`);
      }
    }
    report("entities", p);
  });

  it("5. product behaviour — label is the rendering product, native records are schema-valid", () => {
    const p = new Set<string>();
    const LABEL_TO_ID = new Map(Object.entries(PRODUCT_LABEL).map(([id, l]) => [l, id]));
    const check = (e: TelemetryEvent, company: string, stack: Stack, where: string) => {
      const v = nativeView(e, company, stack);
      if (!v) return;
      const shown = LABEL_TO_ID.get(e.vendor ?? "");
      if (shown && shown !== v.log.sourceId && categoryOf(authoredOf(e))) p.add(`${where} ${authoredOf(e).id}: label "${e.vendor}" but record is ${v.log.sourceId}`);
      for (const x of validateNative(v.log, NATIVE_SOURCES[v.log.sourceId]!.schema).slice(0, 2)) p.add(`${where} ${authoredOf(e).id}: ${v.log.sourceId} ${x.problem} ${x.path}`);
    };
    for (const r of stories()) for (const e of r.events) check(e, r.company, r.stack, `${label(r.company, r.stack)} story:${r.story.id}`);
    for (const t of teams()) for (const e of t.feed) check(e, t.company, t.stack, `team ${label(t.company, t.stack, t.tenant, t.story)}`);
    report("product", p);
  });

  it("6. valid JSON with a raw view — no undefined / NaN / [object Object]", () => {
    const p = new Set<string>();
    const check = (e: TelemetryEvent, company: string, stack: Stack, where: string) => {
      const v = nativeView(e, company, stack);
      const bad: string[] = [];
      if (v) {
        walk(v.log.record, "", bad);
        const round = JSON.parse(JSON.stringify(v.log.record));
        if (JSON.stringify(round) !== JSON.stringify(v.log.record)) bad.push("record does not round-trip through JSON");
        const line = v.log.rawLine?.replace(/\b(src|dst)intfrole="undefined"/g, "");   // FortiOS tunnel interface role
        if (line !== undefined && (!line.trim() || /\bundefined\b|NaN|\[object Object\]/.test(line))) bad.push(`rawLine: ${line.slice(0, 60)}`);
      } else {
        walk(e.raw ?? {}, "raw", bad);
        const raw = toRawLog(enrichEvent(e, 0));
        if (!raw.text?.trim() || /\bundefined\b|\[object Object\]/.test(raw.text)) bad.push(`raw view (${raw.format}) empty or broken`);
      }
      for (const b of bad.slice(0, 3)) p.add(`${where} ${authoredOf(e).id} ${v ? v.log.sourceId : "legacy"}: ${b}`);
    };
    for (const r of stories()) for (const e of r.events) check(e, r.company, r.stack, `${label(r.company, r.stack)} story:${r.story.id}`);
    for (const t of teams()) for (const e of t.feed.slice(0, 400)) check(e, t.company, t.stack, `team ${label(t.company, t.stack, t.tenant, t.story)}`);
    report("json", p);
  });

  it("7. no repeated log inside a story or a team session", () => {
    const p = new Set<string>();
    const fp = (e: TelemetryEvent) => JSON.stringify([e.source, e.event_type, e.hostname, e.user_email, e.src_ip, e.dst_ip, e.description,
      e.process?.cmdline, e.file?.path, e.network?.url]);
    for (const r of stories()) {
      const seen = new Map<string, string>();
      for (const e of r.events) { const k = fp(e); if (seen.has(k)) p.add(`${label(r.company, r.stack)} story:${r.story.id}: ${authoredOf(e).id} repeats ${seen.get(k)}`); else seen.set(k, authoredOf(e).id); }
    }
    for (const t of teams()) {
      // A repeat is the SAME authored log rendered twice (keyed on its origin id) — a burst of
      // genuinely-distinct rows (failed logins, recon requests) is realistic and not a repeat.
      const seen = new Map<string, number>();
      t.feed.forEach((e, i) => { const a = t.answers[i] as Record<string, unknown>; if (TP(a as unknown as TelemetryEvent)) { const oid = String(a.original_id ?? ""); if (!oid) return; seen.set(oid, (seen.get(oid) ?? 0) + 1); } });
      for (const [k, n] of seen) if (n > 1) p.add(`team ${label(t.company, t.stack)}: authored attack log ${k} appears ${n}×`);
    }
    report("repeat", p);
  });

  it("8. attacks land on different employees", () => {
    // The victim draw is random in the product — seed it here so the gate never flaps.
    let seed = 0x2f6b1;
    const rnd = vi.spyOn(Math, "random").mockImplementation(() => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648));
    const p = new Set<string>();
    for (const [company, pool] of COMPANIES) {
      const victimsAll = new Set<string>();
      for (const s of storiesForCompany(company, "medium").slice(0, 8)) {
        const victims = new Set<string>();
        for (let k = 0; k < 12; k++) {
          const evs = instantiateStory(s, pool, edrFor(company, {}), company).events ?? [];
          const counts = new Map<string, number>();
          for (const e of evs) if (e.user_email && TP(e)) counts.set(e.user_email, (counts.get(e.user_email) ?? 0) + 1);
          const v = [...counts].sort((a, b) => b[1] - a[1])[0]?.[0];
          if (v) { victims.add(v); victimsAll.add(v); }
        }
        if (victims.size === 1) p.add(`${company} story:${s.id}: 12 runs, always the same victim ${[...victims][0]}`);
      }
      if (victimsAll.size < 4) p.add(`${company}: only ${victimsAll.size} distinct victims across its stories`);
      // Admin work (SSH / sudo on Linux) lands on someone whose job is IT, never a non-human account.
      const titleOf = new Map(pool.filter(e => e.user_email && e.user_title).map(e => [e.user_email!, e.user_title!] as const));
      for (const s of storiesForCompany(company, "hard").concat(storiesForCompany(company, "medium"))) {
        if (!s.events.some(e => e.source === "linux_audit" && e.user_email)) continue;
        for (let k = 0; k < 6; k++) {
          const evs = instantiateStory(s, pool, edrFor(company, {}), company).events ?? [];
          for (const e of evs) if (e.source === "linux_audit" && e.user_email && /sshd|USER_LOGIN|ssh/i.test(JSON.stringify(e.raw))) {
            const u = e.user_email, t = titleOf.get(u) ?? "";
            if (/(^|[-._])(svc|service|replication|backup|device|scanner|bot|daemon)([-._@]|$)/i.test(u)) p.add(`${company} story:${s.id}: admin SSH by non-human account ${u}`);
            else if (t && !/admin|engineer|devops|it\b|sysadmin|infrastructure|sre|security|network|platform|operations/i.test(t)) p.add(`${company} story:${s.id}: admin SSH by ${u} (${t})`);
          }
        }
      }
    }
    for (const t of teams()) {
      const byIncident = new Map<string, Set<string>>();
      t.feed.forEach((e, i) => { const inc = t.answers[i].incident_id as string | undefined; if (inc && e.user_email && TP(t.answers[i] as unknown as TelemetryEvent)) (byIncident.get(inc) ?? byIncident.set(inc, new Set()).get(inc)!).add(e.user_email); });
      const main = [...byIncident.values()].map(s => [...s][0]);
      if (main.length > 1 && new Set(main).size === 1) p.add(`team ${label(t.company, t.stack)}: all ${main.length} concurrent incidents hit ${main[0]}`);
    }
    rnd.mockRestore();
    report("victims", p);
  });

  it("9. every attack is backed by real, rendered evidence", () => {
    const p = new Set<string>();
    for (const r of stories()) {
      const tp = r.events.filter(STORY_ATTACK);
      if (tp.length === 0) { p.add(`${label(r.company, r.stack)} story:${r.story.id}: no attack log at all`); continue; }
      const evidenced = tp.filter(e => nativeView(e, r.company, r.stack) || Object.keys(e.raw ?? {}).length >= 3);
      if (evidenced.length < tp.length) {
        for (const e of tp.filter(x => !evidenced.includes(x))) p.add(`${label(r.company, r.stack)} story:${r.story.id} ${authoredOf(e).id}: attack log with no evidence record`);
      }
      if (Object.keys(r.stack).length) for (const e of tp) {
        const cat = categoryOf(authoredOf(e));
        if (cat && ["edr", "firewall", "vpn", "idp", "collab", "email_security", "dns"].includes(cat) && !nativeView(e, r.company, r.stack)) p.add(`${label(r.company, r.stack)} story:${r.story.id} ${authoredOf(e).id}: chosen ${cat} product shows no record`);
      }
    }
    report("evidence", p);
  });

  it("10. the team report measures escalations against the real incidents", () => {
    for (const company of ["nexacorp", "medcore"]) {
      const roster: RosterMember[] = [
        { user_id: "u-t1", role: "t1", status: "active", name: "T One", handle: null },
        { user_id: "u-t2", role: "t2", status: "active", name: "T Two", handle: null },
      ];
      const tl = buildTeamTimeline(company, "medium", `measure-${company}`, null, teamLoad("medium", [{ role: "t1" }, { role: "t2" }]), {});
      const t0 = Date.parse("2026-10-02T08:00:00Z");
      let seq = 1;
      const evs: Ev[] = [{ seq: seq++, type: "session.started", actor_id: null, role: null, payload: {}, occurred_at: new Date(t0).toISOString() }];
      const feed = tl.filter(x => x.channel === "feed").slice(0, 160);
      const ids: { id: string; atk: boolean; inc?: string; at: number }[] = [];
      for (const x of feed) {
        const at = t0 + x.due_offset_ms;
        const payload = { ...(x.body as Record<string, unknown>), ...(x.answer ?? {}) };
        evs.push({ seq: seq++, type: "feed.event", actor_id: null, role: null, payload, occurred_at: new Date(at).toISOString() });
        ids.push({ id: String((x.body as { id: string }).id), atk: ["tp", "escalate"].includes(String(payload.expected_verdict)), inc: payload.incident_id as string | undefined, at });
      }
      const attacks = ids.filter(i => i.atk);
      const incidents = [...new Set(attacks.map(a => a.inc).filter(Boolean))];
      expect(incidents.length, `${company}: the timeline has real incidents`).toBeGreaterThan(0);
      // T1 escalates one log of the FIRST incident only, plus one benign log (a false alarm); T2 acknowledges both.
      const caught = attacks.find(a => a.inc === incidents[0])!;
      const benign = ids.find(i => !i.atk)!;
      for (const target of [caught, benign]) {
        const at = target.at + 60_000;
        evs.push({ seq: seq++, type: "escalation.requested", actor_id: "u-t1", role: "t1", payload: { event_id: target.id, summary: "Escalating for review", severity: "high" }, occurred_at: new Date(at).toISOString() });
        evs.push({ seq: seq++, type: "escalation.acknowledged", actor_id: "u-t2", role: "t2", payload: { event_id: target.id }, occurred_at: new Date(at + 30_000).toISOString() });
      }
      evs.sort((a, b) => Date.parse(a.occurred_at!) - Date.parse(b.occurred_at!)).forEach((e, i) => { e.seq = i + 1; });
      const r = computeReport(evs, roster) as unknown as { team: { incidentsTotal: number; incidentsDetected: number; detected: boolean; escalations: number; acknowledged: number }; perUser: { user_id: string; falseAlarms: { eid?: string }[] }[] };
      expect(r.team.incidentsTotal, `${company}: report counts the real incidents`).toBe(incidents.length);
      expect(r.team.incidentsDetected, `${company}: exactly the escalated incident is caught`).toBe(1);
      expect(r.team.detected).toBe(true);
      expect(r.team.escalations).toBe(2);
      expect(r.team.acknowledged).toBe(2);
      const t1 = r.perUser.find(u => u.user_id === "u-t1")!;
      expect(t1.falseAlarms.length, `${company}: the benign escalation is a false alarm`).toBe(1);
    }
  });
});
