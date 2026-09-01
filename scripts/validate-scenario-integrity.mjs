#!/usr/bin/env node
/**
 * Scenario DATA-INTEGRITY gate — complements validate-scenarios (content) and
 * validate-logs (field fidelity). Born from the Sept-2026 external realism audit,
 * which found three whole findings that a single build-time check would have caught:
 *
 *   F-03  chronology — events must be ordered by `ts`; effect must not precede cause.
 *   F-04  taxonomy   — `source` must be a valid LogSource, and a vendor must map to
 *                      exactly one source (no "Workday :: soar", no GitHub as
 *                      CloudTrail, no two spellings of the same product).
 *   F-06  invented   — raw blocks must not carry fields no real product emits (and
 *                      which, in every audited case, handed the analyst the answer).
 *
 *   npm run validate:scenarios:integrity
 */
import { pathToFileURL } from "node:url";
import path from "node:path";

const ROOT = process.cwd();
const { SCENARIOS } = await import(
  pathToFileURL(path.join(ROOT, "src/lib/sim/scenarios.ts")).href
);

const VALID_SOURCES = new Set([
  "edr","sysmon","av","windows_security","linux_audit",
  "firewall","ids","vpn","proxy","dns","dhcp","nac","waf",
  "ad","okta","iam","mfa",
  "o365","gws","cloudtrail","cloud_azure","cloud_gcp",
  "exchange","sharepoint","teams","email_gateway",
  "dlp","ueba","threat_intel","db_monitor","siem","soar",
  "hr","vcs","virtualization","infra_monitor",
  "k8s_audit",
]);

// Raw field keys that no real product emits — inventions that also leak the answer.
// (F-06; matched case-insensitively against the full dotted key.)
const INVENTED_FIELD_PATTERNS = [
  /(^|\.)domain\.registration_age_days$/i,
  /(^|\.)ec2\.mining_pool$/i,
  /(^|\.)mining\.instances_affected$/i,
  /userdata\.decoded_preview$/i,
  /(^|\.)crowdstrike\.behaviors$/i,
  /extendedproperties\.usual sign-in country$/i,
  /extendedproperties\.usual download volume$/i,
  /extendedproperties\.correlated signals$/i,
  /(^|\.)data\.top_output$/i,
];
// Internal platform event ids must never appear inside a raw value shown to the
// student (they break the illusion and hand over the correlation map).
const INTERNAL_ID_RE = /\bevt_[a-z0-9_]+\b/i;

// Known-wrong vendor→category mappings the audit named explicitly (F-04). Key is a
// lowercased vendor substring; value is the source it must NOT be filed under.
const WRONG_MAPPINGS = [
  { vendor: "workday",       badSource: "soar",         note: "Workday is HR, not SOAR" },
  { vendor: "zabbix",        badSource: "siem",         note: "Zabbix is infra monitoring, not SIEM" },
  { vendor: "github",        badSource: "cloudtrail",   note: "GitHub audit is not AWS CloudTrail" },
  { vendor: "vcenter",       badSource: "iam",          note: "vCenter is vSphere, not IAM" },
  { vendor: "esxi",          badSource: "linux_audit",  note: "ESXi is vSphere, not Linux auditd" },
  { vendor: "advanced security", badSource: "threat_intel", note: "GitHub Advanced Security is secret scanning, not threat intel" },
];

// Normalise a vendor label so two spellings of one product collide (F-04).
const normVendor = (v) => String(v || "").toLowerCase()
  .replace(/^(microsoft|fortinet|cisco|palo alto networks|palo alto|vmware|amazon|aws|google)\s+/,"")
  .replace(/\s+/g, " ").trim();

const findings = [];
const add = (sev, slug, where, msg) => findings.push({ sev, slug, where, msg });

// vendor(normalised) -> { sources:Set, spellings:Set }
const vendorIndex = new Map();

for (const def of SCENARIOS) {
  let b;
  try { b = def.build(); } catch (e) { add("ERROR", def.slug, "build()", String(e).slice(0,120)); continue; }
  const slug = def.slug;
  const events = b.events ?? [];

  // ── F-03 chronology ──────────────────────────────────────────────────────
  let prev = -Infinity, prevId = null;
  for (const e of events) {
    const t = new Date(e.ts).getTime();
    if (Number.isNaN(t)) { add("ERROR", slug, e.id, `unparseable ts "${e.ts}"`); continue; }
    if (t < prev && !e.is_baseline) {
      add("ERROR", slug, e.id,
        `out of chronological order (ts ${e.ts} < previous ${prevId}); if this is a baseline event set is_baseline:true, otherwise reorder by ts`);
    }
    prev = Math.max(prev, t); prevId = e.id;
  }

  // ── F-04 taxonomy + F-06 invented fields ─────────────────────────────────
  for (const e of events) {
    if (!VALID_SOURCES.has(e.source)) add("ERROR", slug, e.id, `source "${e.source}" is not a valid LogSource`);

    const vraw = e.vendor ?? "";
    const vn = normVendor(vraw);
    if (vn) {
      if (!vendorIndex.has(vn)) vendorIndex.set(vn, { sources: new Map(), spellings: new Set() });
      const rec = vendorIndex.get(vn);
      rec.spellings.add(vraw);
      rec.sources.set(e.source, (rec.sources.get(e.source) || 0) + 1);
    }
    for (const w of WRONG_MAPPINGS) {
      if (vn.includes(w.vendor) && e.source === w.badSource) {
        add("ERROR", slug, e.id, `${vraw} filed under source "${e.source}" — ${w.note}`);
      }
    }

    const raw = e.raw ?? {};
    for (const [k, v] of Object.entries(raw)) {
      if (INVENTED_FIELD_PATTERNS.some(re => re.test(k))) {
        add("ERROR", slug, e.id, `raw field "${k}" is not emitted by any real product (invented enrichment — move to a separate Enrichment panel)`);
      }
      if (typeof v === "string" && INTERNAL_ID_RE.test(v)) {
        add("ERROR", slug, e.id, `raw field "${k}" leaks an internal platform event id ("${v.match(INTERNAL_ID_RE)[0]}")`);
      }
    }
  }
}

// ── F-04 cross-corpus consistency (after the full sweep) ─────────────────────
for (const [vn, rec] of vendorIndex) {
  if (rec.sources.size > 1) {
    add("ERROR", "(corpus)", vn, `vendor mapped to ${rec.sources.size} different sources: ${[...rec.sources.keys()].join(", ")} — a vendor must map to exactly one source`);
  }
  if (rec.spellings.size > 1) {
    add("WARN", "(corpus)", vn, `vendor has ${rec.spellings.size} spellings: ${[...rec.spellings].join(" / ")} — pick one canonical label`);
  }
}

const errors = findings.filter(f => f.sev === "ERROR");
const warns  = findings.filter(f => f.sev === "WARN");
console.log(`\x1b[1mScenario integrity gate\x1b[0m   ${SCENARIOS.length} scenarios`);
console.log(`  errors ${errors.length}   warnings ${warns.length}`);
for (const f of findings) {
  const c = f.sev === "ERROR" ? "\x1b[31m" : "\x1b[33m";
  console.log(`  ${c}${f.sev}\x1b[0m ${f.slug} · ${f.where} — ${f.msg}`);
}
if (errors.length) { console.log(`\x1b[31m  FAIL — ${errors.length} integrity defect(s).\x1b[0m`); process.exit(1); }
console.log(`\x1b[32m  PASS — scenario data integrity clean.\x1b[0m`);
