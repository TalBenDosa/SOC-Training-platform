/**
 * Scenario integrity audit.
 *
 * The platform's core promise is that an attack STORY is simulated in LOGS, and
 * the analyst reconstructs it and writes a report. That promise breaks in ways
 * no typecheck can see, so this checks the four that matter:
 *
 *   1. DUPLICATION  — the same event reused across scenarios, or within one.
 *   2. LOGIC        — timestamps out of order, or a story that ends before it
 *                     starts.
 *   3. STORY        — a briefing and a debrief narrative actually exist.
 *   4. ALIGNMENT    — the entities the narrative NAMES (hosts, users, IPs,
 *                     files) actually appear in the events. This is the one
 *                     that catches "the story says the attacker used
 *                     svc_backup, but no event mentions svc_backup" — a
 *                     scenario that cannot be solved from its own logs.
 *
 * Reported as findings, not assertions: some overlap between scenarios is
 * legitimate (a corporate proxy IP recurs), so this ranks and explains rather
 * than failing blindly.
 */
import { pathToFileURL } from "node:url";
import path from "node:path";
import crypto from "node:crypto";

const ROOT = process.cwd();
const imp = f => import(pathToFileURL(path.join(ROOT, f)).href);
const m = await imp("src/lib/sim/scenarios.ts");

const findings = [];
const add = (sev, where, msg) => findings.push({ sev, where, msg });

const bundles = [];
for (const s of m.SCENARIOS) {
  const b = m.buildScenarioBySlug(s.slug);
  if (!b) { add("ERROR", s.slug, "buildScenarioBySlug returned nothing"); continue; }
  bundles.push({ slug: s.slug, b });
}

// ── 1. Duplication ──────────────────────────────────────────────────────────
// Fingerprint on the raw block, which is the actual telemetry. Two events with
// the same raw are the same log line, whatever the surrounding prose says.
const seen = new Map();
for (const { slug, b } of bundles) {
  const within = new Map();
  for (const e of b.events ?? []) {
    const raw = JSON.stringify(e.raw ?? {});
    if (raw === "{}" ) continue;
    const h = crypto.createHash("sha1").update(raw).digest("hex").slice(0, 12);

    if (within.has(h)) add("ERROR", `${slug}/${e.id ?? "?"}`,
      `identical raw block to ${within.get(h)} in the same scenario`);
    else within.set(h, e.id ?? "?");

    if (seen.has(h) && seen.get(h).slug !== slug) {
      add("WARN", `${slug}/${e.id ?? "?"}`,
        `identical raw block to ${seen.get(h).slug}/${seen.get(h).id} — copy-paste across scenarios`);
    } else if (!seen.has(h)) seen.set(h, { slug, id: e.id ?? "?" });
  }
}

// Near-duplicate narratives / briefings — a story reused with names swapped.
for (let i = 0; i < bundles.length; i++)
  for (let j = i + 1; j < bundles.length; j++) {
    const a = (bundles[i].b.briefing ?? "").toLowerCase();
    const c = (bundles[j].b.briefing ?? "").toLowerCase();
    if (a && a === c) add("ERROR", `${bundles[i].slug} + ${bundles[j].slug}`, "identical briefing text");
  }

// ── 1b. Cryptographic coherence: one SHA256 = one file ──────────────────────
// A hash is an identity. If two differently-named files share one, or one file
// carries two hashes, the corpus teaches that hash pivoting is unreliable —
// while several scenarios explicitly teach the opposite in their explanations.
//
// The common failure is subtler than a copy-paste: a signed system binary's
// PROCESS hash gets set to the hash of the PAYLOAD it executed, so a student
// pivoting on the process hash concludes rundll32.exe or powershell.exe is
// malware. Both process images and file blocks are checked here.
const hashToNames = new Map();
const nameToHashes = new Map();
for (const { slug, b } of bundles) {
  for (const e of b.events ?? []) {
    const seen = [];
    if (e.file?.sha256) seen.push([e.file.sha256, e.file.name ?? e.file.path ?? "?"]);
    if (e.process?.hash?.sha256) seen.push([e.process.hash.sha256, e.process.name ?? "?"]);
    for (const [h, name] of seen) {
      const base = String(name).split(/[\\/]/).pop().toLowerCase();
      if (!hashToNames.has(h)) hashToNames.set(h, new Set());
      hashToNames.get(h).add(`${base}`);
      const key = `${slug}::${base}`;
      if (!nameToHashes.has(key)) nameToHashes.set(key, new Set());
      nameToHashes.get(key).add(h);
    }
  }
}
for (const [h, names] of hashToNames) {
  if (names.size > 1)
    add("ERROR", `hash ${h.slice(0, 12)}…`,
      `one SHA256 describes ${names.size} different files: ${[...names].join(", ")}`);
}
for (const [key, hashes] of nameToHashes) {
  if (hashes.size > 1)
    add("ERROR", key, `one file carries ${hashes.size} different SHA256 values`);
}

// ── 1c. No analyst conclusions inside raw log blocks ────────────────────────
// A raw block is what a sensor wrote. Sensors do not write MITRE mappings,
// verdicts, or the name of the attack. 172 of these were removed in one pass:
// every Windows Security event in the corpus carried `threat.technique.name`,
// which meant scenarios asking "which technique is this?" printed the answer in
// the telemetry the student was reading.
//
// The event's TYPED `mitre_technique` field is untouched and deliberately not
// checked here — that is platform metadata used for grading and never rendered
// as a log field.
// The KEY check is deliberately narrow. My first version matched any
// `*.Description` field and immediately flagged `crowdstrike.detection.description`
// and `pe.description` — both REAL vendor fields (the latter is PE file
// metadata). Had I trusted it, I would have stripped legitimate telemetry to
// satisfy my own gate. Only fields that no sensor emits are errors here.
const CONCLUSION_KEY = /^(threat\.(technique|tactic)\.|threat\.name$|is_malicious$|attack_type$|.*_verdict$)/i;

// Whether a description field LEAKS is about its contents, not its name. A
// detection description saying "Suspicious process access to lsass.exe" is what
// the product writes; one saying "USB mounted, followed by bulk copy within
// seconds — classic exfiltration" is the analyst's correlation handed over.
// This is a WARN because the line is a judgement call and the reviewer, not the
// gate, should make it.
const ANALYSIS_VALUE = /\b(classic|clearly|obviously|indicates? (an?|the) (attack|intrusion|compromise)|this is (an?|the)|attacker (is|has|was)|exfiltrat\w+ (attempt|activity)|followed by .* within seconds)\b/i;
for (const { slug, b } of bundles) {
  for (const e of b.events ?? []) {
    for (const [k, v] of Object.entries(e.raw ?? {})) {
      if (CONCLUSION_KEY.test(k)) {
        add("ERROR", `${slug}/${e.id ?? "?"}`,
          `raw block carries "${k}" — a conclusion, not something a sensor writes`);
      } else if (typeof v === "string" && v.length > 40 && ANALYSIS_VALUE.test(v)) {
        add("WARN", `${slug}/${e.id ?? "?"}`,
          `raw field "${k}" reads like analysis rather than observation: "${v.slice(0, 80)}"`);
      }
    }
  }
}

// ── 1d. Event descriptions: observation, not instruction ────────────────────
// The description is the console summary line an analyst reads before opening
// the raw block. It states what was OBSERVED. Two failure modes:
//
//  - INSTRUCTIONAL VOICE ("Read X and Y together before deciding…", "Compare
//    this record with evt_03…"). This performs the correlation step the graded
//    question exists to assess, and it was present on 34 events. It reads as
//    helpfulness, which is why it survived review for so long.
//  - LENGTH. A console line is one or two sentences. Anything past ~240
//    characters is a paragraph, and a paragraph is where conclusions hide.
//
// Both are WARN, not ERROR: the boundary is a writing judgement and a regex
// should flag it for a human, not block a merge over a comma.
// Anchored to sentence start, because the damaging form is the IMPERATIVE
// addressed to the reader. My first version matched "read the" anywhere, and
// immediately fired on "The CI pipeline read the production database password
// from AWS Secrets Manager" — an ordinary subject-verb-object observation.
// Had I acted on that finding I would have rewritten a correct description to
// satisfy a bad regex.
// The imperative must be followed by a LOWERCASE word. That single constraint
// removes the two false positives this check produced on its first run:
//
//   "The CI pipeline read the production database password from Secrets Manager"
//        -> ordinary subject-verb-object, not an instruction
//   "Check Point IPS dropped inbound traffic from 91.108.4.222"
//        -> "Check Point" is the vendor's name
//
// A coaching sentence continues in lowercase ("Read the record…", "Compare
// every field…"); a vendor name continues in capitals. Both near-misses would
// have had me rewriting correct descriptions to satisfy a bad regex.
const INSTRUCTIONAL = new RegExp(
  "(^|[.;]\\s+)(read|compare|note|notice|check|consider|look)\\s+(the|this|these|that|every|each|what|whether|at the|for the)\\b"
  + "|\\byou will (meet|see|find) (the|these|this|it)\\b"
  + "|\\bbefore you (decide|describe|conclude|answer)\\b"
  + "|\\b(ask yourself|pay attention|keep in mind|hold on to)\\b",
);

for (const { slug, b } of bundles) {
  for (const e of b.events ?? []) {
    const d = String(e.description ?? "");
    if (!d) { add("WARN", `${slug}/${e.id ?? "?"}`, "event has no description"); continue; }
    if (INSTRUCTIONAL.test(d)) {
      add("WARN", `${slug}/${e.id ?? "?"}`,
        `description coaches the reader rather than reporting an observation: "${d.slice(0, 90)}"`);
    }
    if (d.length > 260) {
      add("WARN", `${slug}/${e.id ?? "?"}`,
        `description is ${d.length} chars — a console line, not a paragraph`);
    }
  }
}

// ── 2. Logic ────────────────────────────────────────────────────────────────
for (const { slug, b } of bundles) {
  const ts = (b.events ?? []).map(e => e.ts ?? e.timestamp).filter(Boolean).map(t => new Date(t).getTime());
  if (ts.some(Number.isNaN)) add("ERROR", slug, "an event timestamp does not parse");
  // NOTE: authoring order is deliberately NOT checked. ScenarioClient sorts by
  // `ts` before rendering (ScenarioClient.tsx:300), so events authored grouped
  // by log source still reach the analyst in time order. An earlier version of
  // this audit flagged 11 scenarios for it — all false positives.
  if (ts.length > 1) {
    const span = (Math.max(...ts) - Math.min(...ts)) / 3600000;
    if (span > 24 * 30) add("WARN", slug, `story spans ${Math.round(span / 24)} days — long for one incident`);
  }
  const n = (b.events ?? []).length;
  if (n < 6) add("WARN", slug, `only ${n} events — thin for reconstructing a story from logs`);
}

// ── 3. Story present ────────────────────────────────────────────────────────
for (const { slug, b } of bundles) {
  if (!b.briefing) add("ERROR", slug, "no briefing — the analyst opens the ticket with no context");
  if (!b.narrative) add("ERROR", slug, "no narrative — nothing to debrief with after submission");
  if ((b.questions ?? []).length < 3) add("WARN", slug, `${(b.questions ?? []).length} questions`);
  for (const q of b.questions ?? []) {
    if (!Array.isArray(q.options) || q.options.length < 2) continue;
    const opts = q.options.map(o => (typeof o === "string" ? { value: o, label: o } : o));
    const ans = Array.isArray(q.answer) ? q.answer : [q.answer];

    for (const a of ans) {
      if (!opts.some(o => o.value === a)) add("ERROR", `${slug}/${q.id ?? "?"}`, `answer "${a}" matches no option`);
    }

    // Answerable by shape alone.
    //
    // Measured at 71% guessable before this existed: the correct answer was
    // the FIRST option in 79 of 112 questions, and in 34 of them it was also
    // far the longest — worst case 4.96x, a 114-character containment action
    // beside two 23-character throwaways.
    //
    // Position is now handled at render time (options are shuffled), but
    // LENGTH is a property of the data and has to be enforced here.
    //
    // Multi-select aware: compares the longest CORRECT option against the
    // longest distractor, since with several right answers any of them being
    // conspicuously long gives the set away.
    //
    // The fix when this fires is to EXPAND the distractors into equally
    // specific wrong actions — never to trim the correct answer, whose
    // specificity is the teaching content.
    const right = opts.filter(o => ans.includes(o.value));
    const wrong = opts.filter(o => !ans.includes(o.value));
    if (right.length && wrong.length) {
      const rl = Math.max(...right.map(o => String(o.label).length));
      const wl = Math.max(...wrong.map(o => String(o.label).length));
      if (rl > wl * 1.45) {
        add("ERROR", `${slug}/${q.id ?? "?"}`,
          `correct option is ${Math.round((rl / wl) * 100)}% of the longest distractor — answerable without reading`);
      }
    }
  }
}

// ── 4. Story ↔ log alignment ────────────────────────────────────────────────
// Pull the concrete entities out of the narrative and check the events mention
// them. A name in the story that appears nowhere in the telemetry means the
// analyst is expected to conclude something the logs never showed.
// Identifiers only. An earlier version matched any hyphenated token, which
// swept up ordinary English compound adjectives — "second-stage",
// "nation-state", "freshly-registered" — and reported them as missing
// hostnames. That produced 20+ findings of which nearly all were noise, and
// noise at that volume hides the two real ones.
//
// A real entity in this corpus looks like an identifier, not like prose: it
// carries a digit, an underscore, a dotted username (j.chen), a file
// extension, an IP, or a domain. Hyphenated pairs of dictionary words do not
// qualify, so they are no longer matched at all rather than being chased with
// an ever-growing stop-list.
const ENTITY = [
  { kind: "ip",       re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
  { kind: "file",     re: /\b[\w-]+\.(?:exe|dll|ps1|bat|vbs|js|zip|7z|dmp|aspx|jsp|sh|py)\b/gi },
  { kind: "domain",   re: /\b[a-z0-9-]{3,}\.(?:com|net|org|io|ru|cn|xyz|top|info)\b/gi },
  { kind: "user",     re: /\b[a-z]{1,2}\.[a-z]{3,}\b/gi },              // j.chen, ab.smith
  { kind: "account",  re: /\b[a-z][a-z0-9]*_[a-z0-9_]{2,}\b/gi },        // svc_backup, libnetpulse_core
  { kind: "host",     re: /\b[a-z][a-z0-9]*-?[a-z0-9]*\d{2,}\b/gi },     // WKS-4471, SRV12
];
// Tokens that look like identifiers but are vocabulary, not entities.
//
// Threat-actor designations (APT29, UNC3944, FIN7…) belong here specifically:
// they legitimately appear in the debrief narrative and legitimately do NOT
// appear in raw telemetry. Attribution is an analyst's conclusion drawn from
// tradecraft, never a field a sensor writes. Flagging them as "named in the
// story but missing from the logs" inverts the actual lesson.
const ATTACKER_NAME = /^(apt|unc|fin|ta|temp|g)\d{2,5}$/i;
const STOP = new Set(["t1078", "t1190", "t1059", "t1083", "t1110", "t1621", "t1558", "t1550", "t1098"]);

for (const { slug, b } of bundles) {
  const blob = JSON.stringify(b.events ?? []).toLowerCase();
  const story = `${b.narrative ?? ""}`;
  const missing = [];
  for (const { kind, re } of ENTITY) {
    for (const mt of story.matchAll(re)) {
      const tok = mt[0].toLowerCase();
      if (STOP.has(tok) || ATTACKER_NAME.test(tok) || tok.length < 5) continue;
      if (!blob.includes(tok)) missing.push(`${tok} (${kind})`);
    }
  }
  const uniq = [...new Set(missing)];
  if (uniq.length) {
    add(uniq.length >= 4 ? "ERROR" : "WARN", slug,
      `narrative names ${uniq.length} entit${uniq.length === 1 ? "y" : "ies"} absent from the logs: ${uniq.slice(0, 6).join(", ")}${uniq.length > 6 ? " …" : ""}`);
  }
}

// ── 5. The SAME rules over the dashboard's LIVE feed ────────────────────────
//
// The live feed is the other half of the platform: 699 events that a student
// triages in real time. Every rule above applies to it just as much, and until
// now none of them did — so the two corpora were drifting apart. The live feed
// was carrying MITRE ATT&CK ids inside WAF raw blocks, which no WAF emits.
//
// One deliberate difference, and it matters: `threat.name` is NOT flagged here.
// On these events it holds genuine vendor signature names — Trojan.GenericKD,
// CobaltStrike.beacon.v4, SQLInjection — which is exactly what SentinelOne,
// CrowdStrike and AWS WAF actually write. That is the opposite of the scenario
// corpus, where the same key held MITRE technique NAMES dressed as signatures.
// Same field, different content, different verdict. A gate that cannot tell
// them apart would have deleted real telemetry.
const liveMods = [
  ["benignEvents", "src/app/(app)/dashboard/benignEvents.ts"],
  ["companyProfiles", "src/lib/sim/companyProfiles.ts"],
];
const liveEvents = [];
for (const [, file] of liveMods) {
  let mod;
  try { mod = await imp(file); } catch { continue; }
  const walk = (o, d = 0) => {
    if (!o || d > 6) return;
    if (Array.isArray(o)) return o.forEach(x => walk(x, d + 1));
    if (typeof o === "object") {
      if (o.raw && o.description !== undefined) liveEvents.push(o);
      Object.values(o).forEach(x => walk(x, d + 1));
    }
  };
  Object.values(mod).forEach(v => walk(v));
}

// Deduplicate — the same event object is reachable through several exports.
const seenLive = new Set();
const live = liveEvents.filter(e => {
  const k = e.id ?? JSON.stringify(e.raw);
  if (seenLive.has(k)) return false;
  seenLive.add(k); return true;
});

// ATT&CK ids belong on the platform's typed field, never in a vendor payload.
const LIVE_CONCLUSION = /^(threat\.(technique|tactic)\.|is_malicious$|attack_type$|.*_verdict$)/i;
for (const e of live) {
  for (const k of Object.keys(e.raw ?? {})) {
    if (LIVE_CONCLUSION.test(k)) {
      add("ERROR", `live/${e.id ?? "?"}`,
        `raw block carries "${k}" — a conclusion, not something a sensor writes`);
    }
  }
  const d = String(e.description ?? "");
  if (INSTRUCTIONAL.test(d)) {
    add("WARN", `live/${e.id ?? "?"}`,
      `description coaches the reader rather than reporting an observation: "${d.slice(0, 90)}"`);
  }
  if (d.length > 260) {
    add("WARN", `live/${e.id ?? "?"}`, `description is ${d.length} chars — a console line, not a paragraph`);
  }
}

// One hash = one file, over the live corpus too.
const liveHash = new Map();
for (const e of live) {
  for (const [h, name] of [[e.file?.sha256, e.file?.name], [e.process?.hash?.sha256, e.process?.name]]) {
    if (!h) continue;
    if (!liveHash.has(h)) liveHash.set(h, new Set());
    liveHash.get(h).add(String(name ?? "?").split(/[\\/]/).pop().toLowerCase());
  }
}
for (const [h, names] of liveHash) {
  if (names.size > 1)
    add("ERROR", `live/hash ${h.slice(0, 12)}…`,
      `one SHA256 describes ${names.size} different files: ${[...names].join(", ")}`);
}

// ── Report ──────────────────────────────────────────────────────────────────
const errors = findings.filter(f => f.sev === "ERROR");
const warns  = findings.filter(f => f.sev === "WARN");
const scenarioEventCount = bundles.reduce((a, x) => a + (x.b.events ?? []).length, 0);
console.log(`\n\x1b[1mTelemetry audit\x1b[0m   ${bundles.length} scenarios / ${scenarioEventCount} events   +   live feed / ${live.length} events`);
console.log(`  errors ${errors.length}   warnings ${warns.length}\n`);
for (const f of errors) console.log(`\x1b[31m  ERROR  ${f.where}\n         ${f.msg}\x1b[0m`);
for (const f of warns)  console.log(`\x1b[33m  WARN   ${f.where}\n         ${f.msg}\x1b[0m`);
if (!errors.length) console.log("\x1b[32m  PASS — no blocking scenario defects.\x1b[0m");
process.exit(errors.length ? 1 : 0);
