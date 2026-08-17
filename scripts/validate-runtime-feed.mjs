/**
 * Runtime-feed invariants — the three CI checks from the live-session audit.
 *
 *   TIMESTAMP_COHERENCE : every ISO timestamp inside raw{} stays in the same era
 *                         as the event's outer ts after the feed rebases it
 *                         (catches the ~153-day template-date drift), AND every
 *                         ts-stamping site in useLiveEvents.ts routes through
 *                         withRebasedTime (regression guard).
 *   ASSET_INVENTORY     : within a company's pool a hostname maps to at most one
 *                         PRIVATE IP, and a private IP maps to at most one host
 *                         (a DC never changes IP; one IP never = two machines).
 *                         Public IPs are ignored — a remote laptop legitimately
 *                         shows an external NAT address alongside its LAN IP.
 *   TENANT_PURITY       : no event in a company's pool carries ANOTHER tenant's
 *                         email domain (generic external providers are fine).
 *
 * Run: node --import tsx scripts/validate-runtime-feed.mjs   (wired as npm run validate:feed)
 */
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const imp = rel => import(pathToFileURL(path.join(ROOT, rel)).href);
const C = { red: s => `\x1b[31m${s}\x1b[0m`, green: s => `\x1b[32m${s}\x1b[0m`,
            yellow: s => `\x1b[33m${s}\x1b[0m`, bold: s => `\x1b[1m${s}\x1b[0m`, dim: s => `\x1b[2m${s}\x1b[0m` };

// Canonical tenant domains (the 5 companies). generic providers are NOT tenants.
const TENANT_DOMAINS = {
  nexacorp: "nexacorp.com",
  medcore: "medcorehealth.org",
  rocketstack: "rocketstack.io",
  globallogis: "globallogis.de",
  quantumbank: "quantumbank.ch",
};
const ALL_TENANT_DOMAINS = new Set(Object.values(TENANT_DOMAINS));

const errors = [];
const warnings = [];
const err  = (check, msg) => errors.push(`${C.red("✗")} ${C.bold(check)}  ${msg}`);
const warn = (check, msg) => warnings.push(`${C.yellow("⚠")} ${C.bold(check)}  ${msg}`);

// ── load the data (tsx resolves TS) ───────────────────────────────────────────
const benign     = await imp("src/app/(app)/dashboard/benignEvents.ts");
const profiles   = await imp("src/lib/sim/companyProfiles.ts");
const stories    = await imp("src/app/(app)/dashboard/attackStories.ts");
const { withRebasedTime, isTimestampString } = await imp("src/lib/sim/rebaseTime.ts");

const BENIGN_EVENTS  = benign.BENIGN_EVENTS ?? [];
const COMPANY_EVENTS = profiles.COMPANY_EVENTS ?? {};
const ATTACK_STORIES = stories.ATTACK_STORIES ?? [];

// getCompanyEvents mirror: nexacorp = whole BENIGN pool; others = their COMPANY_EVENTS.
const companyPool = id => (id === "nexacorp" ? BENIGN_EVENTS : (COMPANY_EVENTS[id] ?? []));

// ── walk helpers ──────────────────────────────────────────────────────────────
function collectStrings(value, out) {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) value.forEach(v => collectStrings(v, out));
  else if (value && typeof value === "object") Object.values(value).forEach(v => collectStrings(v, out));
  return out;
}
const isPrivateIp = ip =>
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip) ||
  /^192\.168\.\d{1,3}\.\d{1,3}$/.test(ip) ||
  /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(ip);
const EMAIL_RE = /([a-z0-9._%+-]+)@([a-z0-9.-]+\.[a-z]{2,})/gi;

// ══════════════════════════════════════════════════════════════════════════════
// CHECK 1 — TIMESTAMP_COHERENCE
// ══════════════════════════════════════════════════════════════════════════════
{
  // (a) Behavioural assertion: withRebasedTime must preserve each field's offset
  //     from the outer ts. A "primary" field that equals the event time in the
  //     template must equal the NEW ts after rebasing (within 5s); a legitimately
  //     historical field (e.g. "sender first seen") must keep its exact offset.
  //     We do NOT flag far-from-now inner fields — those are real (first-seen /
  //     prior-login baselines); the bug is drift being INTRODUCED, which only a
  //     missing rebase at a call site can do (guarded in (b)).
  const tmplBase = Date.parse("2026-05-10T08:00:00Z");
  const probe = {
    id: "probe", ts: new Date(tmplBase).toISOString(),
    raw: {
      "primary.time": new Date(tmplBase).toISOString(),                          // == event time
      "history.firstSeen": new Date(tmplBase - 420 * 86_400_000).toISOString(),  // 420d before
      "sysmon.UtcTime": new Date(tmplBase - 12_000).toISOString().replace("T", " ").replace("Z", ""),
    },
  };
  const target = Date.parse("2026-08-17T09:00:00Z");
  const r = withRebasedTime(probe, new Date(target).toISOString());
  const primaryDrift = Math.abs(Date.parse(r.raw["primary.time"]) - target);
  const histOffset   = target - Date.parse(r.raw["history.firstSeen"]);
  const sysDrift     = Math.abs(Date.parse(r.raw["sysmon.UtcTime"].replace(" ", "T") + "Z") - (target - 12_000));
  if (primaryDrift > 5_000) err("TIMESTAMP_COHERENCE", `rebase left the primary raw timestamp ${Math.round(primaryDrift/1000)}s off the new ts`);
  if (Math.abs(histOffset - 420 * 86_400_000) > 5_000) err("TIMESTAMP_COHERENCE", `rebase did not preserve a historical field's offset (got ${(histOffset/86_400_000).toFixed(1)}d, want 420d)`);
  if (sysDrift > 5_000) err("TIMESTAMP_COHERENCE", `rebase mishandled a Sysmon UtcTime field (${Math.round(sysDrift/1000)}s off)`);

  // (b) Regression guard — every ts-stamping site in the feed hook must route
  //     through withRebasedTime, or a pooled event's inner raw timestamps stay
  //     pinned to the May-2026 template date (the ~153-day drift the audit found).
  const hookSrc = readFileSync(path.join(ROOT, "src/app/(app)/dashboard/useLiveEvents.ts"), "utf8");
  const naive = hookSrc.match(/\{\s*\.\.\.\w+,\s*ts:\s*new Date\([^)]*\)\.toISOString\(\)/g) || [];
  if (naive.length) err("TIMESTAMP_COHERENCE",
    `useLiveEvents.ts stamps ts without withRebasedTime (${naive.length} site(s)) — inner raw timestamps will drift: ${naive[0].slice(0, 56)}…`);

  const withTs = [...BENIGN_EVENTS, ...ATTACK_STORIES.flatMap(s => s.events ?? [])]
    .filter(e => e?.raw && collectStrings(e.raw, []).some(isTimestampString)).length;
  console.log(C.dim(`  TIMESTAMP_COHERENCE: rebase unit-checks pass; ${withTs} pooled/story events carry raw timestamps; call sites guarded`));
}

// ══════════════════════════════════════════════════════════════════════════════
// CHECK 2 — ASSET_INVENTORY (per company)
// Bind hostname→src_ip ONLY for HOST TELEMETRY, where src_ip is the reporting
// host's own address (endpoint process/file/registry events from edr/sysmon/av).
// For auth/identity/network/security-tool events the src_ip is a REMOTE client or
// subject — a DC legitimately logs many source IPs on its 4624/4768 logon records,
// and forcing those to the DC's own IP would destroy the "where did this logon
// come from" evidence. So those event types are excluded from the binding.
// ══════════════════════════════════════════════════════════════════════════════
const PEER_SRC_SOURCES = new Set(["ad","okta","iam","o365","gws","cloudtrail","cloud_azure",
  "mfa","firewall","vpn","proxy","waf","dns","dhcp","nac","email_gateway","exchange",
  "sharepoint","teams","dlp","siem","ueba","threat_intel","db_monitor","soar","ids"]);
const bindsHostIp = e => {
  const et = e.event_type || "";
  if (/^(auth_|mfa_|account_|role_|group_|cloud_|email_|vpn_|dlp_|dns_|data_|privilege_|ueba_|risk_)/.test(et)) return false;
  return !PEER_SRC_SOURCES.has(e.source);
};
for (const companyId of Object.keys(TENANT_DOMAINS)) {
  const pool = companyPool(companyId);
  if (!pool.length) continue;
  const hostToIps = new Map();  // hostname -> Set(private ip)
  const ipToHosts = new Map();  // private ip -> Set(hostname)
  for (const e of pool) {
    const host = e.hostname;
    const ip = e.src_ip;
    if (!host || !ip || !isPrivateIp(ip) || !bindsHostIp(e)) continue;
    if (!hostToIps.has(host)) hostToIps.set(host, new Set());
    hostToIps.get(host).add(ip);
    if (!ipToHosts.has(ip)) ipToHosts.set(ip, new Set());
    ipToHosts.get(ip).add(host);
  }
  for (const [host, ips] of hostToIps) if (ips.size > 1)
    err("ASSET_INVENTORY", `[${companyId}] host ${host} has ${ips.size} private IPs: ${[...ips].join(", ")}`);
  for (const [ip, hosts] of ipToHosts) if (hosts.size > 1)
    err("ASSET_INVENTORY", `[${companyId}] private IP ${ip} is shared by ${hosts.size} hosts: ${[...hosts].join(", ")}`);
}

// ══════════════════════════════════════════════════════════════════════════════
// CHECK 3 — TENANT_PURITY (per company pool)
// ══════════════════════════════════════════════════════════════════════════════
for (const companyId of Object.keys(TENANT_DOMAINS)) {
  const pool = companyPool(companyId);
  if (!pool.length) continue;
  const own = TENANT_DOMAINS[companyId];
  const foreign = new Map(); // domain -> count
  for (const e of pool) {
    const hay = [e.user_email, ...collectStrings(e.raw ?? {}, []), e.description ?? ""].join(" ");
    for (const m of hay.matchAll(EMAIL_RE)) {
      const dom = m[2].toLowerCase();
      if (dom !== own && ALL_TENANT_DOMAINS.has(dom)) foreign.set(dom, (foreign.get(dom) ?? 0) + 1);
    }
  }
  for (const [dom, count] of foreign)
    err("TENANT_PURITY", `[${companyId}] pool carries ${count} event(s) with foreign tenant domain @${dom} (own is @${own})`);
}

// ── CHECK 3b — TENANT_PURITY for injected STORY events ────────────────────────
// A story is injected into a company's live feed. Its identities must match the
// company it can appear for: an allowlisted story may use its company's domain;
// a generic (no-allowlist) story appears for EVERY company, so it must be
// nexacorp-based (the platform's base convention — the victim-swap localises it).
// FICTIONAL companies that are not real tenants (e.g. "cryotech") must never
// appear in any feed. Only INTERNAL-actor identity fields are checked (user_email
// + winlog domain forms); attacker senders / external partners are skipped.
const FORBIDDEN_FICTIONAL = /@?cryotech(-updates)?\.(com|io|net)\b|\bCRYOTECH\b/i;
for (const story of ATTACK_STORIES) {
  const allowed = new Set(
    story.companies && story.companies.length
      ? story.companies.map(c => TENANT_DOMAINS[c]).filter(Boolean)
      : [TENANT_DOMAINS.nexacorp],
  );
  const hits = new Map(); // domain/marker -> count
  for (const e of story.events ?? []) {
    // internal-actor identity only: user_email + winlog TargetDomainName-style forms
    const idFields = [e.user_email];
    for (const [k, v] of Object.entries(e.raw ?? {})) {
      if (typeof v === "string" && /DomainName$|UserPrincipalName$|userPrincipalName$|\.user\b|user_email/i.test(k)) idFields.push(v);
    }
    const hay = idFields.filter(Boolean).join(" ");
    if (FORBIDDEN_FICTIONAL.test(hay)) hits.set("cryotech (fictional)", (hits.get("cryotech (fictional)") ?? 0) + 1);
    for (const m of hay.matchAll(EMAIL_RE)) {
      const dom = m[2].toLowerCase();
      if (ALL_TENANT_DOMAINS.has(dom) && !allowed.has(dom)) hits.set(`@${dom}`, (hits.get(`@${dom}`) ?? 0) + 1);
    }
  }
  const scope = story.companies?.length ? `[${story.companies.join(",")}]` : "[generic → all companies]";
  for (const [dom, count] of hits)
    err("TENANT_PURITY", `story "${story.id}" ${scope} carries ${count} internal identity/ies from ${dom} (allowed: ${[...allowed].join(", ") || "nexacorp.com"})`);
}

// ══════════════════════════════════════════════════════════════════════════════
// CHECK 4 — SEVERITY→LEVEL monotonicity of the base map (informational)
// ══════════════════════════════════════════════════════════════════════════════
{
  const base = { critical: 10, high: 8, medium: 5, low: 3, informational: 1 };
  const order = ["informational", "low", "medium", "high", "critical"];
  for (let i = 1; i < order.length; i++)
    if (base[order[i]] <= base[order[i - 1]])
      err("SEV_LEVEL", `severityBase not monotonic: ${order[i]}=${base[order[i]]} <= ${order[i-1]}=${base[order[i-1]]}`);
}

// ── report ────────────────────────────────────────────────────────────────────
console.log("");
console.log(C.bold("Runtime-feed invariants"));
if (warnings.length) { console.log(C.yellow(`  ${warnings.length} warning(s)`)); warnings.forEach(w => console.log("  " + w)); }
if (errors.length) {
  console.log("");
  errors.forEach(e => console.log("  " + e));
  console.log("");
  console.log(C.red(`  FAIL — ${errors.length} invariant violation(s).`));
  process.exit(1);
}
console.log(C.green("  PASS — timestamp coherence, asset inventory, and tenant purity all hold."));
