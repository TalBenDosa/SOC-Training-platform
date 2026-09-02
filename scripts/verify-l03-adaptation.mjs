#!/usr/bin/env node
/**
 * L-03 verification — do attack chains, after instantiateStory adaptation, still
 * leak the fact that they were authored for a DIFFERENT company?
 *
 * Replicates the live dashboard resolve path (page.tsx resolveStory → built-in
 * branch) for every built-in company across difficulties and many RNG draws, then
 * scans each adapted event for four leak channels:
 *   1. EDR vendor field != the company's declared EDR
 *   2. vendor-specific RAW KEY PREFIX of a foreign EDR (e.g. crowdstrike.* on a
 *      SentinelOne shop) — the field-level vendor swap does NOT rewrite these
 *   3. a user email whose domain belongs to ANOTHER built-in company
 *   4. a hostname that isn't part of the company's own asset pool
 * Also scans raw+description TEXT for foreign company domains / foreign EDR tokens.
 */
import { pathToFileURL } from "node:url";
import path from "node:path";

// Match production behaviour (and silence the dev-only "sources missing" warnings
// pickStoryForCompany prints outside production).
process.env.NODE_ENV = "production";

const ROOT = process.cwd();
const imp = (p) => import(pathToFileURL(path.join(ROOT, p)).href);

const { pickStoryForCompany, instantiateStory } = await imp("src/app/(app)/dashboard/attackStories.ts");
const { COMPANY_EVENTS } = await imp("src/lib/sim/companyProfiles.ts");
const { BENIGN_EVENTS } = await imp("src/app/(app)/dashboard/benignEvents.ts");
const { COMPANY_PROFILES } = await imp("src/lib/sim/companyProfilesMeta.ts");

const profById = new Map(COMPANY_PROFILES.map((p) => [p.id, p]));
const SERVICE = /(svc[-_.]|service|system|daemon|noreply|no-reply|backup|scanner|agent@)/i;

// Replicate getCompanyEvents (page.tsx) exactly.
function getCompanyEvents(id) {
  const base = id === "nexacorp" ? BENIGN_EVENTS : COMPANY_EVENTS[id] ?? BENIGN_EVENTS;
  const active = new Set(profById.get(id)?.architecture?.sources ?? []);
  return base.filter((e) => e.source !== "dns" && (active.size === 0 || active.has(e.source)));
}

const domainOf = (email) => (email && email.includes("@") ? email.split("@")[1].toLowerCase() : null);

// Each company's own email domain = most common non-service domain in its pool.
function ownDomain(id) {
  const c = new Map();
  for (const e of getCompanyEvents(id)) {
    if (e.user_email && !SERVICE.test(e.user_email)) {
      const d = domainOf(e.user_email);
      if (d) c.set(d, (c.get(d) ?? 0) + 1);
    }
  }
  return [...c.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
}
function hostSet(id) {
  return new Set(getCompanyEvents(id).map((e) => e.hostname).filter(Boolean));
}

const COMPANIES = COMPANY_PROFILES.map((p) => p.id).filter((id) => id !== "nexacorp");
const DIFFS = ["easy", "medium", "hard"];
const ITER = 150;

const ownDomains = new Map(COMPANIES.map((id) => [id, ownDomain(id)]));
const foreignDomains = new Set([...ownDomains.values()].filter(Boolean));
const hostSets = new Map(COMPANIES.map((id) => [id, hostSet(id)]));
// Foreign NetBIOS/realm short-names (DOMAIN\user) — every company id + the default.
const allNetbios = new Set([...COMPANIES, "nexacorp"].map((id) => id.toUpperCase()));

// Distinctive EDR product tokens for raw-key / text detection.
const EDR_TOKENS = {
  crowdstrike: /crowdstrike|falcon|CrowdStrike/i,
  sentinelone: /sentinelone|(^|[^a-z])s1[._]|SentinelOne|Singularity/i,
  sophos: /\bsophos\b|Intercept X/i,
  defender: /defender|\bmde\b|windows_defender|WindowsDefenderAtp/i,
  cortex: /cortex|\bxdr\b|palo.?alto.*xdr/i,
  carbonblack: /carbon.?black|\bcb\.|vmware.?cb/i,
};
function edrTokenOf(edrString) {
  const s = (edrString ?? "").toLowerCase();
  if (s.includes("crowdstrike")) return "crowdstrike";
  if (s.includes("sentinelone")) return "sentinelone";
  if (s.includes("sophos")) return "sophos";
  if (s.includes("defender")) return "defender";
  if (s.includes("cortex")) return "cortex";
  if (s.includes("carbon")) return "carbonblack";
  return null;
}

let totalStories = 0;
const leaks = { edrVendor: [], edrRawKey: [], edrRawText: [], domain: [], host: [], netbios: [] };
const seenExample = new Set();
const addExample = (bucket, key, detail) => {
  if (seenExample.has(bucket + key)) return;
  seenExample.add(bucket + key);
  leaks[bucket].push(detail);
};

for (const id of COMPANIES) {
  const prof = profById.get(id);
  const edr = prof?.architecture?.edr;
  const ownEdrToken = edrTokenOf(edr);
  const own = ownDomains.get(id);
  const hosts = hostSets.get(id);
  const pool = getCompanyEvents(id);

  for (const diff of DIFFS) {
    for (let i = 0; i < ITER; i++) {
      const story = pickStoryForCompany(id, diff);
      const adapted = instantiateStory(story, pool, edr, id);
      totalStories++;

      for (const e of adapted.events) {
        const rawStr = e.raw ? JSON.stringify(e.raw).toLowerCase() : "";
        const procStr = e.process ? JSON.stringify(e.process) : "";
        const rawKeys = e.raw ? Object.keys(e.raw).join(" ").toLowerCase() : "";
        const text = `${e.description ?? ""} ${rawStr} ${procStr.toLowerCase()}`;
        const rawTextForEdr = `${e.description ?? ""} ${rawStr}`.toLowerCase();

        // NetBIOS/realm leak: FOREIGN\ token anywhere (process.user, raw, description)
        for (const nb of allNetbios) {
          if (nb !== id.toUpperCase() && (`${procStr} ${e.description ?? ""} ${e.raw ? JSON.stringify(e.raw) : ""}`).includes(nb + "\\")) {
            addExample("netbios", `${id}:${nb}`, `${id} ← foreign NetBIOS "${nb}\\" (process.user/raw)`);
          }
        }

        // 1. EDR vendor field
        if (e.source === "edr" && e.vendor && edr && e.vendor !== edr) {
          addExample("edrVendor", `${id}:${e.vendor}`, `${id} (${edr}) ← edr event vendor="${e.vendor}"`);
        }
        // 2. foreign EDR raw-KEY prefix (crowdstrike.* on a SentinelOne shop)
        if (e.source === "edr") {
          for (const [tok, re] of Object.entries(EDR_TOKENS)) {
            if (tok !== ownEdrToken && re.test(rawKeys)) {
              const hit = rawKeys.split(" ").find((k) => re.test(k)) ?? tok;
              addExample("edrRawKey", `${id}:${tok}`, `${id} (${edr}) ← edr raw key "${hit}" (${tok})`);
            }
          }
        }
        // 3. an email domain belonging to another company (user_email OR process.user OR raw)
        for (const d of [domainOf(e.user_email), ...[...`${procStr} ${rawStr}`.matchAll(/@([a-z0-9.-]+\.[a-z]{2,})/g)].map((m) => m[1])]) {
          if (d && d !== own && foreignDomains.has(d)) {
            addExample("domain", `${id}:${d}`, `${id} (own=${own}) ← email domain "${d}" (another company)`);
          }
        }
        // 4. hostname not in company asset pool
        if (e.hostname && hosts.size > 0 && !hosts.has(e.hostname)) {
          addExample("host", `${id}:${e.hostname}`, `${id} ← hostname "${e.hostname}" not in asset pool`);
        }
        // 5. foreign EDR token in an EDR event's raw VALUES / description
        if (e.source === "edr") {
          for (const [tok, re] of Object.entries(EDR_TOKENS)) {
            if (tok !== ownEdrToken && re.test(rawTextForEdr)) {
              const where = re.test((e.description ?? "").toLowerCase()) ? "desc" : "rawval";
              const snip = (e.description ?? "").toLowerCase().match(re) ? `desc="${e.description}"` : `raw=${rawStr.slice(0, 160)}`;
              addExample("edrRawText", `${id}:${tok}:${where}`, `${id} (${edr}) ← foreign EDR "${tok}" [${where}] ${snip}`);
            }
          }
        }
      }
    }
  }
}

const totalLeaks = Object.values(leaks).reduce((n, a) => n + a.length, 0);
console.log(`\nL-03 adaptation verification — ${totalStories} adapted stories across ${COMPANIES.length} companies × ${DIFFS.length} difficulties × ${ITER} draws\n`);
for (const [k, arr] of Object.entries(leaks)) {
  console.log(`  ${k.padEnd(11)} ${arr.length === 0 ? "clean" : arr.length + " distinct leak(s)"}`);
  for (const d of arr.slice(0, 12)) console.log(`      • ${d}`);
}
console.log(totalLeaks === 0 ? "\n  PASS — no cross-company leaks after adaptation.\n" : `\n  FAIL — ${totalLeaks} distinct leak channel instances remain.\n`);
process.exit(totalLeaks === 0 ? 0 : 1);
