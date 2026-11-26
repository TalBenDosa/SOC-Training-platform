#!/usr/bin/env node
/**
 * Mechanical checker for staged track content (used by the soc-track-builder agent).
 *
 * A staging folder holds one sub-folder per topic, each with lesson.json, room.json and
 * evidence.json. This script checks everything a machine can check before the content is
 * assembled into the repo: JSON shape, word counts, quiz option balance, the quiz map
 * (every graded item points at a sentence that literally exists in the teaching text),
 * banned characters and phrases, telemetry enums, log fields against the vendor registry,
 * and XP sums. What it cannot check (is the claim true?) is the evidence ledger's job.
 *
 *   node scripts/track-builder/check-staging.mjs <folder>          # a topic folder or a track folder
 *   node scripts/track-builder/check-staging.mjs <folder> --max-readings 3
 *   node scripts/track-builder/check-staging.mjs <folder> --integrated     # re-check after assembling
 *
 * Exit 0 = clean, 1 = errors.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isSyntheticHex } from "../lib/syntheticHash.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const argv = process.argv.slice(2);
const target = argv.find(a => !a.startsWith("--"));
if (!target) { console.error("usage: check-staging.mjs <staging folder> [--max-readings N]"); process.exit(2); }
const mr = argv.indexOf("--max-readings");
const MAX_READINGS = mr >= 0 ? Number(argv[mr + 1]) : 3;
// --integrated: the staged content is already assembled into the repo, so its own ids
// exist in the generated indexes; skip the "already exists" checks.
const INTEGRATED = argv.includes("--integrated");

// ── repo facts ──────────────────────────────────────────────────────────────
const typesSrc = fs.readFileSync(path.join(ROOT, "src/lib/sim/types.ts"), "utf8");
const union = name => {
  const m = typesSrc.match(new RegExp(`export type ${name} =([\\s\\S]*?);`));
  return new Set([...m[1].matchAll(/"([^"]+)"/g)].map(x => x[1]));
};
const LOG_SOURCES = union("LogSource");
const EVENT_TYPES = union("EventType");
const SEVERITIES = union("Severity");
const registry = JSON.parse(fs.readFileSync(path.join(ROOT, "scripts/log-field-registry.json"), "utf8"));
const roomsMeta = fs.readFileSync(path.join(ROOT, "src/data/roomsMeta.ts"), "utf8");
const metaRooms = JSON.parse(roomsMeta.slice(roomsMeta.indexOf("= [") + 2, roomsMeta.lastIndexOf("]") + 1));
const ROOM_LEVEL = new Map(metaRooms.map(r => [r.id, r.difficulty]));
const EXISTING_TASK_IDS = new Set(metaRooms.flatMap(r => r.tasks.map(t => t.id)));
const libSrc = fs.readFileSync(path.join(ROOT, "src/data/libraryIndex.ts"), "utf8");
const lib = JSON.parse(libSrc.slice(libSrc.indexOf("= [") + 2, libSrc.lastIndexOf("]") + 1));
const LESSON_IDS = new Set(lib.map(l => l.id)); const LESSON_SLUGS = new Set(lib.map(l => l.slug));
const LESSON_TOPICS = new Set(lib.map(l => l.topic)); const ROOM_CATEGORIES = new Set(metaRooms.map(r => r.category));
const LEVEL = { beginner: 1, intermediate: 2, advanced: 3 };

const commonExact = new Set((registry.commonFields ?? []).filter(f => !f.endsWith(".")));
const commonPrefixes = (registry.commonFields ?? []).filter(f => f.endsWith("."));
const denied = (registry.deniedFields ?? []).map(d => d.field);
function vendorIndex(extra) {
  const idx = new Map();
  const all = { ...registry.vendors, ...extra };
  for (const [key, v] of Object.entries(all)) {
    idx.set(key.toLowerCase(), key); if (v.label) idx.set(v.label.toLowerCase(), key);
    for (const a of v.aliases ?? []) idx.set(a.toLowerCase(), key);
  }
  return { idx, all };
}
function resolveVendor(idx, declared) {
  if (!declared) return null;
  const lower = declared.toLowerCase().trim();
  if (idx.has(lower)) return idx.get(lower);
  let best = null;
  for (const [alias, key] of idx) {
    if (alias.length < 4) continue;
    if (lower.includes(alias) && (!best || alias.length > best.alias.length)) best = { alias, key };
  }
  return best ? best.key : null;
}
function fieldAllowed(all, key, f) {
  if (denied.some(d => (d.endsWith(".") ? f.startsWith(d) : f === d))) return false;
  if (commonExact.has(f) || commonPrefixes.some(p => f.startsWith(p))) return true;
  const v = all[key]; if (!v) return false;
  return (v.exactFields ?? []).includes(f) || (v.prefixes ?? []).some(p => f.startsWith(p));
}

// ── helpers ─────────────────────────────────────────────────────────────────
const words = s => String(s ?? "").trim().split(/\s+/).filter(Boolean).length;
const squash = s => String(s ?? "").replace(/\s+/g, " ").trim();
const allStrings = (o, out = []) => {
  if (typeof o === "string") out.push(o);
  else if (Array.isArray(o)) o.forEach(x => allStrings(x, out));
  else if (o && typeof o === "object") Object.values(o).forEach(x => allStrings(x, out));
  return out;
};
const CONCLUSION_FIELD = /(^|[._])(is_?malicious|verdict|threat_?score|risk_?score|anomaly|anomalous|baseline|deviation|suspicious|is_?attack|confidence_?score|ml_?score)([._]|$)/i;
const SELF_INCRIMINATING = /\b(attacker|hacker|evil|malicious|malware|backdoor|exfil|stolen|pwn)/i;
const DOC_NET = /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/;
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/;

function checkTopic(dir) {
  const errs = []; const warns = [];
  const E = (w, m) => errs.push(`${w}: ${m}`); const W = (w, m) => warns.push(`${w}: ${m}`);
  const load = f => {
    const p = path.join(dir, f);
    if (!fs.existsSync(p)) { E(f, "missing"); return null; }
    const text = fs.readFileSync(p, "utf8");
    try { return { json: JSON.parse(text), text }; } catch (e) { E(f, `invalid JSON: ${e.message}`); return null; }
  };
  const L = load("lesson.json"), R = load("room.json"), V = load("evidence.json");
  if (!L || !R || !V) return { errs, warns };
  const lesson = L.json, room = R.json, ev = V.json;

  // ── text hygiene, both files ──
  for (const [name, obj, text] of [["lesson", lesson, L.text], ["room", room, R.text]]) {
    const { references: _refs, ...learnerFacing } = obj;
    const strs = allStrings(learnerFacing);
    if (/[—–]/.test(text)) E(name, "contains an em dash or en dash; use a colon, comma or full stop");
    if (/[‘’“”]/.test(text)) E(name, "contains smart quotes; use plain ASCII quotes");
    if (/[​ ]/.test(text)) E(name, "contains a zero-width or non-breaking space");
    // placeholderHashes.test.ts rejects hand-typed looking digests (a1b2c3..., patterned runs).
    for (const m of text.matchAll(/[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32}/g)) if (isSyntheticHex(m[0])) E(name, `hex value looks hand-typed: ${m[0]} (run scripts/track-builder/fix-staging-hashes.mjs on the track folder)`);
    for (const s of strs) {
      const short = s.slice(0, 70).replace(/\n/g, " ");
      if (/https?:\/\/(?![^\s"')]*\.example\b)/.test(s) && !/"?(url|Url|BackendUrl|RequestUri|requestUrl)/.test(s) && name === "lesson" && !looksLikeLog(s)) W(name, `URL in learner-facing text: "${short}"`);
      if (/\b(about|around|roughly|takes?|in)\s+\d+\s*(minutes?|mins?|hours?)\s+(to (read|complete|finish)|of reading)/i.test(s)) E(name, `time estimate in text: "${short}"`);
      if (/\b(HACK THE SOC|Hack The SOC|HackTheSOC)\b/.test(s)) E(name, `names the platform: "${short}"`);
      if (/\b(further reading|references?:)\s*$/im.test(s)) E(name, `reference-list heading in text: "${short}"`);
      if (/\b(TODO|TBD|lorem ipsum|placeholder)\b/i.test(s)) E(name, `placeholder text: "${short}"`);
    }
    if (name === "room" && R.text.includes("`")) E("room", "backtick character in room text (rooms do not render inline code)");
  }
  function looksLikeLog(s) { return /^\s*[{\[]/.test(s) || /\n\s*"?[\w.]+"?\s*[:=]/.test(s); }

  // ── lesson ──
  const at = "lesson";
  if (!/^topic-lesson-[a-z0-9-]+$/.test(lesson.id ?? "")) E(at, "id must be topic-lesson-<slug>");
  if (lesson.id !== `topic-lesson-${lesson.slug}`) W(at, "id is not topic-lesson-<slug> of its own slug");
  if (!INTEGRATED && (LESSON_IDS.has(lesson.id) || LESSON_SLUGS.has(lesson.slug))) E(at, "id or slug already exists in the library");
  if (!LESSON_TOPICS.has(lesson.topic)) W(at, `topic "${lesson.topic}" is not an existing library topic`);
  if (!LEVEL[lesson.difficulty]) E(at, "difficulty must be beginner, intermediate or advanced");
  if (lesson.kind !== "lesson") E(at, 'kind must be "lesson"');
  const iw = words(lesson.intro);
  if (iw < 140 || iw > 330) E(at, `intro is ${iw} words (150 to 300)`);
  if (/\?\s*$/.test(String(lesson.intro).split(/(?<=[.?!])\s/)[0] ?? "")) E(at, "intro opens with a question; open by defining the topic");
  const secs = lesson.sections ?? [];
  if (secs.length < 7 || secs.length > 9) E(at, `${secs.length} sections (7 to 9)`);
  secs.forEach((s, i) => {
    const w = words(s.content);
    if (w < 380 || w > 600) E(`${at}:s${i + 1}`, `${w} words (400 to 550)`);
    if (!s.heading || s.heading.length < 4) E(`${at}:s${i + 1}`, "missing heading");
    for (const para of String(s.content).split(/\n\n+/)) {
      if (!/^[|#>\-*\d`]/.test(para.trim()) && words(para) > 150) W(`${at}:s${i + 1}`, `paragraph of ${words(para)} words; split it`);
    }
  });
  if (secs.filter(s => s.codeExample).length < 5) E(at, "fewer than 5 sections carry a codeExample");
  if ((lesson.keyTakeaways ?? []).length !== 5) E(at, "keyTakeaways must have 5 entries");
  const quiz = lesson.quiz ?? [];
  if (quiz.length !== 8) E(at, `${quiz.length} quiz questions (8)`);
  const dist = {};
  quiz.forEach((q, i) => {
    const w = `${at}:q${i + 1}`;
    const vals = (q.options ?? []).map(o => o.value);
    if (vals.join("") !== "abcd") E(w, "options must be four, with values a, b, c, d in order");
    const idx = vals.indexOf(q.answer);
    if (idx < 0) { E(w, "answer matches no option"); return; }
    dist[q.answer] = (dist[q.answer] ?? 0) + 1;
    balance(w, (q.options ?? []).map(o => o.label), idx, E);
    explain(w, q.explanation, E);
  });
  if (quiz.length === 8 && (Object.keys(dist).length < 4 || Math.max(...Object.values(dist)) > 3)) E(at, `quiz answers are not spread across a to d: ${JSON.stringify(dist)}`);
  const refs = lesson.references ?? [];
  if (refs.length < 8) E(at, `${refs.length} references (aim for 10 or more, minimum 8)`);
  if (lesson.researchUsed !== true) E(at, "researchUsed must be true");
  if (typeof lesson.estimatedMinutes !== "number") E(at, "estimatedMinutes must be a number");

  // ── room ──
  const rt = "room";
  if (!INTEGRATED && ROOM_LEVEL.has(room.id)) E(rt, "room id already exists");
  if (!/^[a-z0-9-]+$/.test(room.id ?? "")) E(rt, "room id must be kebab-case");
  if (!LEVEL[room.difficulty]) E(rt, "difficulty must be beginner, intermediate or advanced");
  if (!ROOM_CATEGORIES.has(room.category)) E(rt, `category "${room.category}" is not an existing room category`);
  for (const p of room.prerequisites ?? []) {
    if (!ROOM_LEVEL.has(p)) W(rt, `prerequisite "${p}" is not an existing room (fine only if it is a sibling room earlier in this track)`);
    else if (LEVEL[ROOM_LEVEL.get(p)] > LEVEL[room.difficulty]) E(rt, `prerequisite "${p}" is harder than this room`);
  }
  const tasks = room.tasks ?? [];
  if (tasks.length < 12 || tasks.length > 14) E(rt, `${tasks.length} tasks (12 to 14)`);
  const ids = new Set();
  for (const t of tasks) {
    if (ids.has(t.id)) E(rt, `duplicate task id ${t.id}`);
    if (!INTEGRATED && EXISTING_TASK_IDS.has(t.id)) E(rt, `task id ${t.id} already used by another room`);
    ids.add(t.id);
  }
  const readings = tasks.filter(t => t.type === "reading");
  if (tasks[0]?.type !== "reading") E(rt, "the first task must be a reading");
  if (readings.length > MAX_READINGS) E(rt, `${readings.length} readings; the narration budget allows ${MAX_READINGS}`);
  if (readings.length < 2) E(rt, "fewer than 2 readings");
  tasks.forEach((t, i) => { if (t.type === "reading" && tasks[i + 1]?.type === "reading") E(rt, `two readings in a row at ${t.id}`); });
  const kinds = new Set(tasks.filter(t => t.type !== "reading").map(t => t.type));
  if (kinds.size < 5) E(rt, `only ${kinds.size} graded task types (${[...kinds].join(", ")}); need 5`);
  for (const need of ["question", "log_analysis", "analyst_choice", "matching", "ordering", "flag"]) if (!kinds.has(need)) E(rt, `no ${need} task`);
  if (tasks.filter(t => t.type === "question").length < 2) E(rt, "fewer than 2 question tasks");
  const verdicts = tasks.filter(t => t.type === "analyst_choice").map(t => t.correct_verdict);
  if (!verdicts.some(v => v === "false_positive" || v === "benign_true_positive")) W(rt, "no benign analyst_choice in the room");
  let sum = 0;
  const { idx: vIdx, all: vAll } = vendorIndex(ev.new_vendor ? { [ev.new_vendor.key]: ev.new_vendor } : {});
  // Proposed additions to an existing vendor (a documented field the registry lacks) are
  // accepted here and reported, so the orchestrator can add them to the registry.
  for (const a of ev.registry_additions ?? []) {
    const k = resolveVendor(vIdx, a.vendor);
    if (!k) { E("evidence", `registry_additions: vendor "${a.vendor}" not found`); continue; }
    if (!a.source || !a.field) { E("evidence", "registry_additions entries need vendor, field, source, locator"); continue; }
    vAll[k] = { ...vAll[k], exactFields: [...(vAll[k].exactFields ?? []), a.field] };
    W("evidence", `proposes registry field ${k}: ${a.field}`);
  }
  const ledgerFields = new Set((ev.log_fields ?? []).map(f => f.field));
  const checkEvent = (w, e) => {
    if (!e || typeof e !== "object") { E(w, "missing event"); return; }
    if (!LOG_SOURCES.has(e.source)) E(w, `event.source "${e.source}" is not a LogSource`);
    if (!EVENT_TYPES.has(e.event_type)) E(w, `event.event_type "${e.event_type}" is not an EventType`);
    if (e.severity && !SEVERITIES.has(e.severity)) E(w, `event.severity "${e.severity}" is not a Severity`);
    if (!e.id || !e.ts || Number.isNaN(Date.parse(e.ts))) E(w, "event needs id and an ISO ts");
    if ("expected_verdict" in e) E(w, "event must not carry expected_verdict");
    const key = resolveVendor(vIdx, e.vendor);
    if (!key) { E(w, `vendor "${e.vendor}" is not in the log-field registry (propose new_vendor in evidence.json)`); }
    if (!e.raw || typeof e.raw !== "object" || Object.keys(e.raw).length < 6) E(w, "raw block missing or under 6 fields");
    for (const f of Object.keys(e.raw ?? {})) {
      if (key && !fieldAllowed(vAll, key, f)) E(w, `raw field "${f}" is not registered for ${key}`);
      if (!ledgerFields.has(f)) E(w, `raw field "${f}" has no log_fields entry in evidence.json`);
      if (CONCLUSION_FIELD.test(f)) W(w, `raw field "${f}" looks like a conclusion; keep it only if the product really emits it`);
    }
    for (const s of allStrings(e.raw ?? {})) {
      if (SELF_INCRIMINATING.test(s)) W(w, `raw value looks self-incriminating: "${s.slice(0, 60)}"`);
    }
    for (const ip of [e.src_ip, e.dst_ip, ...allStrings(e.raw ?? {}).filter(s => /^\d{1,3}(\.\d{1,3}){3}$/.test(s))].filter(Boolean)) {
      if (!PRIVATE.test(ip) && !DOC_NET.test(ip)) E(w, `IP ${ip} is neither private nor a documentation range`);
    }
  };
  for (const t of tasks) {
    const w = `${rt}:${t.id}`;
    switch (t.type) {
      case "reading": {
        const n = words(t.content);
        if (n < 360 || n > 600) E(w, `${n} words (380 to 560)`);
        if ("xp" in t) E(w, "readings carry no xp");
        if (!t.checkpoint) E(w, "reading has no checkpoint");
        else {
          if ((t.checkpoint.options ?? []).length !== 4) E(w, "checkpoint needs 4 options");
          balance(`${w}[checkpoint]`, t.checkpoint.options ?? [], t.checkpoint.answer, E);
          if (!t.checkpoint.explanation) E(w, "checkpoint needs an explanation");
        }
        break;
      }
      case "question":
        if ((t.options ?? []).length !== 4) E(w, "needs 4 options");
        if (!(t.answer >= 0 && t.answer < 4)) E(w, "answer index out of range");
        balance(w, t.options ?? [], t.answer, E); explain(w, t.explanation, E); sum += t.xp ?? 0;
        if (!(t.xp > 0)) E(w, "xp missing");
        break;
      case "log_analysis":
        checkEvent(w, t.event);
        if (!t.heading || !t.context) E(w, "needs heading and context");
        if ((t.questions ?? []).length < 2 || t.questions.length > 3) E(w, "needs 2 or 3 questions");
        (t.questions ?? []).forEach((q, i) => {
          if ((q.options ?? []).length !== 4) E(`${w}#${i + 1}`, "needs 4 options");
          balance(`${w}#${i + 1}`, q.options ?? [], q.answer, E); explain(`${w}#${i + 1}`, q.explanation, E);
          if (!(q.xp > 0)) E(`${w}#${i + 1}`, "xp missing"); sum += q.xp ?? 0;
        });
        if ("xp" in t) E(w, "log_analysis carries xp on its questions, not on the task");
        break;
      case "analyst_choice":
        checkEvent(w, t.event);
        if (!["true_positive", "benign_true_positive", "false_positive", "escalate", "informational"].includes(t.correct_verdict)) E(w, "bad correct_verdict");
        if (!t.heading || !t.scenario) E(w, "needs heading and scenario");
        if ((t.correct_verdict === "false_positive" || t.correct_verdict === "benign_true_positive") && !t.fp_trap) E(w, "benign verdict needs fp_trap");
        explain(w, t.explanation, E); if (!(t.xp > 0)) E(w, "xp missing"); sum += t.xp ?? 0;
        break;
      case "matching": {
        const p = t.pairs ?? [];
        if (p.length < 4 || p.length > 6) E(w, "needs 4 to 6 pairs");
        if (new Set(p.map(x => x.right)).size !== p.length || new Set(p.map(x => x.left)).size !== p.length || new Set(p.map(x => x.id)).size !== p.length) E(w, "pair ids, left and right sides must be unique");
        if (!t.heading || !t.instructions) E(w, "needs heading and instructions");
        explain(w, t.explanation, E); if (!(t.xp > 0)) E(w, "xp missing"); sum += t.xp ?? 0;
        break;
      }
      case "ordering": {
        const it = t.items ?? [];
        if (it.length < 4 || it.length > 7) E(w, "needs 4 to 7 items");
        const idset = new Set(it.map(x => x.id));
        if ((t.correct_order ?? []).length !== idset.size || (t.correct_order ?? []).some(x => !idset.has(x)) || new Set(t.correct_order).size !== idset.size) E(w, "correct_order must list every item id once");
        if (JSON.stringify(it.map(x => x.id)) === JSON.stringify(t.correct_order)) E(w, "items are listed already in the correct order; shuffle the items array");
        if (!t.heading || !t.instructions) E(w, "needs heading and instructions");
        explain(w, t.explanation, E); if (!(t.xp > 0)) E(w, "xp missing"); sum += t.xp ?? 0;
        break;
      }
      case "flag":
        if (!t.prompt || !t.answer) E(w, "needs prompt and answer");
        if (!t.hint) E(w, "flag needs a hint");
        else if (squash(t.hint).toLowerCase().includes(squash(t.answer).toLowerCase())) E(w, "hint contains the answer");
        if (String(t.answer).length > 60) E(w, "flag answer too long to type");
        if (!(t.xp > 0)) E(w, "xp missing"); sum += t.xp ?? 0;
        break;
      case "query_fill":
        if (!["kql", "spl", "sigma"].includes(t.language)) E(w, "language must be kql, spl or sigma");
        for (const b of t.blanks ?? []) {
          if (!String(t.template).includes(`{{${b.id}}}`)) E(w, `blank ${b.id} not in template`);
          if (!(b.answers ?? []).length) E(w, `blank ${b.id} has no answers`);
        }
        if (!(t.blanks ?? []).length) E(w, "no blanks");
        explain(w, t.explanation, E); if (!(t.xp > 0)) E(w, "xp missing"); sum += t.xp ?? 0;
        break;
      default: E(w, `task type "${t.type}" is not used by this agent`);
    }
  }
  if (room.xp !== sum) E(rt, `room xp ${room.xp} but graded tasks sum to ${sum}`);

  // ── evidence ──
  const et = "evidence";
  const srcIds = new Set((ev.sources ?? []).map(s => s.id));
  if (srcIds.size < 8) E(et, `${srcIds.size} sources (minimum 8, aim for 10 or more)`);
  for (const s of ev.sources ?? []) if (!/^https:\/\//.test(s.url ?? "")) E(et, `source ${s.id} has no https URL`);
  const srcUrls = new Set((ev.sources ?? []).map(s => s.url));
  for (const r of refs) {
    const u = String(r).match(/https?:\/\/\S+/)?.[0];
    if (!u) E(at, `reference without URL: "${String(r).slice(0, 60)}"`);
    else if (!srcUrls.has(u)) E(at, `reference URL not among evidence sources: ${u}`);
  }
  for (const c of ev.claims ?? []) if (!srcIds.has(c.source)) E(et, `claim cites unknown source ${c.source}: "${String(c.claim).slice(0, 50)}"`);
  if ((ev.claims ?? []).length < 25) E(et, `${(ev.claims ?? []).length} claims in the ledger; a lesson and a room carry far more checkable facts than that`);
  for (const f of ev.log_fields ?? []) if (!srcIds.has(f.source)) E(et, `log field ${f.field} cites unknown source ${f.source}`);
  if (!Array.isArray(ev.unverified)) E(et, "unverified must be an array (empty if nothing)");
  if (!Array.isArray(ev.mitre_ids)) E(et, "mitre_ids must be an array");
  // every ATT&CK / ATLAS id in the text must be in the ledger
  // References are URLs (a technique URL contains its parent's number), so they are not scanned.
  const text = allStrings([{ ...lesson, references: [] }, room]).join("\n");
  const cited = new Set([...text.matchAll(/\b(AML\.T\d{4}(?:\.\d{3})?|AML\.TA\d{4}|TA\d{4}|T\d{4}(?:\.\d{3})?)\b/g)].map(m => m[1]));
  const ledgerIds = new Set((ev.mitre_ids ?? []).map(m => m.id));
  for (const id of cited) if (!ledgerIds.has(id)) E(et, `${id} is cited in the content but missing from mitre_ids`);

  // quiz map: every graded item has a support sentence that exists in the teaching text
  const textOf = ref => {
    if (ref === "lesson:intro") return lesson.intro;
    let m = /^lesson:s(\d+)$/.exec(ref ?? "");
    if (m) { const s = secs[Number(m[1]) - 1]; return s ? `${s.heading}\n${s.content}\n${s.codeExample ?? ""}` : null; }
    m = /^room:(.+)$/.exec(ref ?? "");
    if (m) { const t = tasks.find(x => x.id === m[1] && x.type === "reading"); return t ? `${t.heading}\n${t.content}\n${t.codeExample ?? ""}` : null; }
    return null;
  };
  const expected = [];
  quiz.forEach((_q, i) => expected.push(`lesson:q${i + 1}`));
  for (const t of tasks) {
    if (t.type === "reading") continue;
    if (t.type === "log_analysis") (t.questions ?? []).forEach((_q, i) => expected.push(`room:${t.id}#${i + 1}`));
    else expected.push(`room:${t.id}`);
  }
  const qm = new Map((ev.quiz_map ?? []).map(x => [x.q, x]));
  const sectionsWithQuestion = new Set();
  for (const q of expected) {
    const m = qm.get(q);
    if (!m) { E(et, `quiz_map has no entry for ${q}`); continue; }
    const src = textOf(m.taught_in);
    if (src == null) { E(et, `${q}: taught_in "${m.taught_in}" is not a lesson section or a room reading`); continue; }
    if (!m.support || words(m.support) < 6) { E(et, `${q}: support sentence missing or too short`); continue; }
    if (!squash(src).includes(squash(m.support))) E(et, `${q}: support sentence is not found literally in ${m.taught_in}: "${squash(m.support).slice(0, 70)}"`);
    if (q.startsWith("lesson:")) { if (!m.taught_in.startsWith("lesson:")) E(et, `${q}: a lesson question must be taught in the lesson`); sectionsWithQuestion.add(m.taught_in); }
    else {
      if (!m.taught_in.startsWith("room:")) E(et, `${q}: a room task must be taught by a reading in the same room`);
      else {
        const taskId = q.slice(5).split("#")[0];
        const ti = tasks.findIndex(x => x.id === taskId), ri = tasks.findIndex(x => x.id === m.taught_in.slice(5));
        if (ri > ti) E(et, `${q}: the reading that teaches it (${m.taught_in}) comes after the task`);
      }
    }
  }
  secs.forEach((_s, i) => { if (!sectionsWithQuestion.has(`lesson:s${i + 1}`)) W(at, `section ${i + 1} has no quiz question mapped to it`); });

  return { errs, warns, stats: { lessonWords: words(lesson.intro) + secs.reduce((a, s) => a + words(s.content), 0), roomTasks: tasks.length, readings: readings.length, xp: sum, sources: srcIds.size, claims: (ev.claims ?? []).length, unverified: (ev.unverified ?? []).length } };
}

function balance(w, options, correctIdx, E) {
  if (!Array.isArray(options) || options.length < 2 || typeof options[correctIdx] !== "string") { E(w, "options or answer index invalid"); return; }
  const right = options[correctIdx].length;
  const wrong = options.filter((_, i) => i !== correctIdx).map(o => String(o).length);
  // Stricter than the repo gate (1.7) so content lands with margin.
  if (right > Math.max(...wrong) * 1.45) E(w, `correct option is ${Math.round(right / Math.max(...wrong) * 100)}% of the longest distractor; expand the distractors`);
  if (Math.min(...wrong) > right * 1.45) E(w, "every distractor is much longer than the correct option");
  const norm = s => String(s).toLowerCase().replace(/[\s"'`.,;:()[\]{}|]+/g, " ").trim();
  if (new Set(options.map(norm)).size !== options.length) E(w, "two options differ only by case, spacing or punctuation");
}
function explain(w, text, E) {
  if (!text || String(text).length < 80) { E(w, "explanation missing or too short to teach"); return; }
  if (/\b([Oo]ption|[Aa]nswer|[Cc]hoice)\s+\(?[A-Da-d]\)?(\b|[.,:;])/.test(text) || /(^|[\s(])[A-D]\)? (is|was) (correct|wrong|incorrect|right)\b/.test(text)) E(w, "explanation names an option by letter; name it by content");
}

// ── run ─────────────────────────────────────────────────────────────────────
const abs = path.resolve(target);
const dirs = fs.existsSync(path.join(abs, "lesson.json")) || fs.existsSync(path.join(abs, "room.json"))
  ? [abs]
  : fs.readdirSync(abs, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => path.join(abs, d.name)).sort();
let bad = 0;
const seenRoom = new Map(), seenLesson = new Map(), seenTask = new Map();
for (const d of dirs) {
  const { errs, warns, stats } = checkTopic(d);
  try {
    const r = JSON.parse(fs.readFileSync(path.join(d, "room.json"), "utf8")); const l = JSON.parse(fs.readFileSync(path.join(d, "lesson.json"), "utf8"));
    if (seenRoom.has(r.id)) errs.push(`room id ${r.id} also used in ${seenRoom.get(r.id)}`); seenRoom.set(r.id, path.basename(d));
    if (seenLesson.has(l.id)) errs.push(`lesson id ${l.id} also used in ${seenLesson.get(l.id)}`); seenLesson.set(l.id, path.basename(d));
    for (const t of r.tasks ?? []) { if (seenTask.has(t.id)) errs.push(`task id ${t.id} also used in ${seenTask.get(t.id)}`); seenTask.set(t.id, path.basename(d)); }
  } catch { /* reported above */ }
  console.log(`\n${path.basename(d)}  ${errs.length ? "FAIL" : "ok"}${stats ? `  ${JSON.stringify(stats)}` : ""}`);
  for (const e of errs) console.log(`  ERROR  ${e}`);
  for (const w of warns) console.log(`  warn   ${w}`);
  bad += errs.length;
}
console.log(`\n${dirs.length} topic folder(s), ${bad} error(s)`);
process.exit(bad ? 1 : 0);
