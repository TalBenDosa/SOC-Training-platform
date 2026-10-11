#!/usr/bin/env node
/**
 * Live-feed DATA-INTEGRITY gate. Born from the Sept-2026 "JSON contradictions"
 * audit, which found the same fact written by hand per-event instead of derived,
 * and drifting. Materialises every event the dashboard can show — the 67 scenario
 * builds, the per-company benign + attack pools, and the global benign pool — and
 * enforces four invariants a single hand-edit cannot violate silently:
 *
 *   D-01  one IP → one country     (a src IP paired with two geo countries is a bug)
 *   D-02  no RFC 5737 doc-range IP (192.0.2/198.51.100/203.0.113 resolve to nothing
 *                                   on VirusTotal/GeoIP — the exact pivot we teach)
 *   D-03  one SHA-256 → one file   (a hash on two different filenames is impossible,
 *                                   and a real-malware hash on a benign file misleads)
 *   D-06  uniform timestamp format (all ts carry millisecond precision, so sorting
 *                                   by string can't separate attacks from noise)
 *
 *   npm run validate:feed:integrity
 */
import { pathToFileURL } from "node:url";
import path from "node:path";
process.env.NODE_ENV = "production";
const ROOT = process.cwd();
const imp = (p) => import(pathToFileURL(path.join(ROOT, p)).href);

const { SCENARIOS } = await imp("src/lib/sim/scenarios.ts");
const { COMPANY_EVENTS, COMPANY_ATTACKS } = await imp("src/lib/sim/companyProfiles.ts");
const { BENIGN_EVENTS } = await imp("src/app/(app)/dashboard/benignEvents.ts");

// ── Gather every event, tagged with where it came from ───────────────────────
const all = [];
const chronoViolations = [];
for (const def of SCENARIOS) {
  let b; try { b = def.build(); } catch { continue; }
  const evs = b.events ?? [];
  for (const e of evs) all.push({ e, where: `scenario:${def.slug}` });
  // D-11: a scenario's events must be non-decreasing in time by array order, or a
  // viewer that streams the array jumps backwards in time.
  let worst = 0, count = 0;
  for (let i = 1; i < evs.length; i++) {
    const back = new Date(evs[i - 1].ts).getTime() - new Date(evs[i].ts).getTime();
    if (back > 0) { count++; worst = Math.max(worst, back); }
  }
  if (count > 0) chronoViolations.push({ slug: def.slug, count, worstMin: Math.round(worst / 60000) });
}
for (const [cid, evs] of Object.entries(COMPANY_EVENTS)) for (const e of evs) all.push({ e, where: `benign:${cid}` });
for (const [cid, evs] of Object.entries(COMPANY_ATTACKS)) for (const e of evs) all.push({ e, where: `attack:${cid}` });
for (const e of BENIGN_EVENTS) all.push({ e, where: "benign:global" });

const findings = [];
const add = (sev, code, where, detail) => findings.push({ sev, code, where, detail });

const DOC_RANGE = /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/;
const IP_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/;

// D-01 + D-02
const ipCountry = new Map();   // ip -> Map(country -> Set(where))
const noteIpCountry = (ip, country, where) => {
  if (!ip || !country) return;
  if (!ipCountry.has(ip)) ipCountry.set(ip, new Map());
  const m = ipCountry.get(ip);
  if (!m.has(country)) m.set(country, new Set());
  m.get(country).add(where);
};
// D-03
const hashFiles = new Map();   // sha256 -> Map(filename -> Set(where))
const noteHash = (h, file, where) => {
  if (!h || !/^[0-9a-f]{64}$/i.test(h)) return;
  const f = (file || "").split(/[\\/]/).pop() || "(unknown)";
  if (!hashFiles.has(h)) hashFiles.set(h, new Map());
  const m = hashFiles.get(h);
  if (!m.has(f)) m.set(f, new Set());
  m.get(f).add(where);
};

for (const { e, where } of all) {
  // D-06: ts must have millisecond precision
  if (typeof e.ts === "string" && /T\d{2}:\d{2}(:\d{2})?Z$/.test(e.ts)) {
    add("ERROR", "D-06", where, `ts "${e.ts}" lacks millisecond precision (event ${e.id ?? "?"})`);
  }
  // D-01: src_ip ↔ geo.country
  if (e.src_ip && e.geo?.country) noteIpCountry(e.src_ip, e.geo.country, where);
  // D-02: any documentation-range IP anywhere in the event
  const scan = `${e.src_ip ?? ""} ${e.dst_ip ?? ""} ${e.raw ? JSON.stringify(e.raw) : ""}`;
  for (const m of scan.matchAll(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g)) {
    if (DOC_RANGE.test(m[0])) add("ERROR", "D-02", where, `RFC 5737 documentation IP ${m[0]} used as a routable address (event ${e.id ?? "?"})`);
  }
  // D-02 raw FortiGate srccountry/dstcountry ↔ srcip/dstip
  if (e.raw) {
    const r = e.raw;
    if (r["data.srcip"] && r["data.srccountry"]) noteIpCountry(String(r["data.srcip"]), String(r["data.srccountry"]), where);
    if (r["data.dstip"] && r["data.dstcountry"]) noteIpCountry(String(r["data.dstip"]), String(r["data.dstcountry"]), where);
  }
  // D-03: file hash ↔ filename. Pair a hash ONLY with the filename from its OWN
  // field family (never the process Image or free-text description — a hashed
  // payload dropped by cmd.exe is not a collision with cmd.exe).
  if (e.file?.sha256) noteHash(e.file.sha256, e.file.path || e.file.name || "(structured file)", where);
  if (e.raw) {
    const r = e.raw;
    const pair = (hk, fk) => { if (r[hk] && r[fk]) noteHash(String(r[hk]), String(r[fk]), where); };
    pair("crowdstrike.SHA256HashData", "crowdstrike.FileName");
    pair("crowdstrike.SHA256HashData", "crowdstrike.ImageFileName");
    pair("mde.SHA256", "mde.FileName");
    pair("file.hash.sha256", "file.name");
    pair("file.hash.sha256", "file.path");
    pair("threat.file.hash.sha256", "threat.file.name");
  }
}

// D-01: one IP → one country
for (const [ip, m] of ipCountry) {
  if (m.size > 1) {
    const parts = [...m.entries()].map(([c, ws]) => `${c} [${[...ws].slice(0, 2).join(", ")}]`);
    add("ERROR", "D-01", "geo", `IP ${ip} is labelled with ${m.size} different countries: ${parts.join("  vs  ")}`);
  }
}
// D-03: one hash → one file
for (const [h, m] of hashFiles) {
  if (m.size > 1) {
    add("ERROR", "D-03", "hash", `SHA-256 ${h.slice(0, 16)}… is attached to ${m.size} different files: ${[...m.keys()].join(", ")}`);
  }
}

// D-11: chronology per scenario
for (const c of chronoViolations) {
  add("ERROR", "D-11", `scenario:${c.slug}`, `${c.count} event(s) go backwards in time by array order (worst jump ${c.worstMin} min) — sort by ts`);
}

// ── Report ───────────────────────────────────────────────────────────────────
const byCode = {};
for (const f of findings) (byCode[f.code] ??= []).push(f);
console.log(`\nLive-feed integrity gate — ${all.length} events materialised\n`);
for (const code of ["D-01", "D-02", "D-03", "D-06", "D-11"]) {
  const arr = byCode[code] ?? [];
  console.log(`  ${code}  ${arr.length === 0 ? "clean" : arr.length + " violation(s)"}`);
  for (const f of arr.slice(0, 20)) console.log(`      • ${f.detail}`);
  if (arr.length > 20) console.log(`      … and ${arr.length - 20} more`);
}
const errs = findings.length;
console.log(errs === 0 ? "\n  PASS — live-feed data is internally consistent.\n"
                       : `\n  FAIL — ${errs} integrity violation(s).\n`);
process.exit(errs === 0 ? 0 : 1);
