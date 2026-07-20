#!/usr/bin/env node
/**
 * Room & quiz content gate.
 *
 * Companion to validate-scenarios.mjs. A coverage audit found that 42 of the 82
 * ATT&CK techniques the scenarios make students practise are taught in no room —
 * students were being examined on Kerberoasting, AS-REP roasting and Golden
 * Ticket with no room teaching Kerberos. The checks below encode the authoring
 * rules in src/data/CONTENT-SPEC.md plus that coverage measurement.
 *
 *   npm run validate:content            # errors only
 *   npm run validate:content -- --warnings
 *   npm run validate:content -- --coverage   # the practise-vs-teach report
 */

import { pathToFileURL } from "node:url";
import path from "node:path";

const ROOT = process.cwd();
const imp = f => import(pathToFileURL(path.join(ROOT, f)).href);

const { ROOMS } = await imp("src/data/rooms.ts");
const quizMod = await imp("src/lib/quizzes/data.ts");
// ALL_QUIZZES is the combined catalogue (base + packs). Falling back to QUIZZES
// would silently skip every packaged quiz, which is exactly the kind of blind
// spot this gate exists to prevent.
const QUIZZES = quizMod.ALL_QUIZZES ?? quizMod.QUIZZES ?? [];
const { SCENARIOS } = await imp("src/lib/sim/scenarios.ts");

const findings = [];
const add = (sev, where, msg) => findings.push({ sev, where, msg });

const DEPRECATED = ["T1076", "T1086", "T1064", "T1035", "T1117"];

/** Options answerable by shape alone — the correct one being much the longest. */
function checkOptionBalance(where, options, correctIdx) {
  if (!Array.isArray(options) || options.length < 2) return;
  const right = options[correctIdx];
  if (typeof right !== "string") return;
  const wrong = options.filter((_, i) => i !== correctIdx);
  const longestWrong = Math.max(...wrong.map(o => String(o).length));
  if (right.length > longestWrong * 1.7) {
    add("WARN", where,
      `correct option is ${Math.round(right.length / longestWrong * 100)}% of the longest distractor — answerable without reading`);
  }
}

// ── Quizzes ────────────────────────────────────────────────────────────────
const quizSlugs = new Set();
for (const q of QUIZZES) {
  const at = `quiz/${q.slug}`;
  if (quizSlugs.has(q.slug)) add("ERROR", at, "duplicate quiz slug");
  quizSlugs.add(q.slug);

  const n = (q.questions ?? []).length;
  if (n < 10) add("ERROR", at, `${n} questions — the spec requires 10-12`);
  if (n > 14) add("WARN", at, `${n} questions — longer than the house format`);

  const ids = new Set();
  for (const qq of q.questions ?? []) {
    const w = `${at}/${qq.id}`;
    if (ids.has(qq.id)) add("ERROR", w, "duplicate question id");
    ids.add(qq.id);

    if (!Array.isArray(qq.options) || qq.options.length < 3) {
      add("ERROR", w, "fewer than 3 options");
    } else if (typeof qq.answer !== "number" || qq.answer < 0 || qq.answer >= qq.options.length) {
      add("ERROR", w, `answer index ${qq.answer} is outside options[0..${qq.options.length - 1}]`);
    } else {
      checkOptionBalance(w, qq.options, qq.answer);
      if (new Set(qq.options.map(String)).size !== qq.options.length) {
        add("ERROR", w, "duplicate option text — one distractor is unusable");
      }
    }
    if (!qq.explanation || qq.explanation.length < 40) {
      add("ERROR", w, "explanation missing or too short to teach anything");
    }
    for (const d of DEPRECATED) {
      if (JSON.stringify(qq).includes(d)) add("ERROR", w, `cites deprecated ATT&CK ID ${d}`);
    }
  }
}

// ── Rooms ──────────────────────────────────────────────────────────────────
const roomIds = new Set(ROOMS.map(r => r.id));
for (const r of ROOMS) {
  const at = `room/${r.id}`;
  const tasks = r.tasks ?? [];

  if (tasks.length < 6) add("ERROR", at, `${tasks.length} tasks — too thin to teach a topic`);

  for (const p of r.prerequisites ?? []) {
    if (!roomIds.has(p)) add("ERROR", at, `prerequisite "${p}" is not a real room id`);
  }

  const kinds = new Set(tasks.map(t => t.type));
  if (kinds.size < 3) {
    add("WARN", at, `only ${kinds.size} task type(s) — a room of reading+question is a slideshow`);
  }
  const hasPractice = tasks.some(t => t.type === "log_analysis" || t.type === "analyst_choice");
  if (!hasPractice) {
    add("WARN", at, "no log_analysis or analyst_choice task — reading a log is the job");
  }

  // three readings in a row is a wall of text
  let run = 0;
  for (const t of tasks) {
    run = t.type === "reading" ? run + 1 : 0;
    if (run === 3) { add("WARN", at, "three consecutive reading tasks"); break; }
  }

  // xp accounting
  const sum = tasks.reduce((s, t) => {
    if (typeof t.xp === "number") return s + t.xp;
    if (t.type === "log_analysis") return s + (t.questions ?? []).reduce((a, x) => a + (x.xp ?? 0), 0);
    return s;
  }, 0);
  // The app awards xp per task and has no completion bonus (verified against
  // RoomClient.tsx), so the room's stated xp must equal the task sum exactly —
  // anything else overstates what a student can actually earn.
  if (typeof r.xp === "number" && sum > 0 && r.xp !== sum) {
    add("ERROR", at, `room xp ${r.xp} but tasks sum to exactly ${sum} — the card overstates earnable XP`);
  }

  for (const t of tasks) {
    const w = `${at}/${t.id}`;
    if (t.type === "question") {
      if (!Array.isArray(t.options) || typeof t.answer !== "number" ||
          t.answer < 0 || t.answer >= t.options.length) {
        add("ERROR", w, "answer index outside options");
      } else checkOptionBalance(w, t.options, t.answer);
    }
    if (t.type === "ordering") {
      const itemIds = new Set((t.items ?? []).map(i => i.id));
      for (const id of t.correct_order ?? []) {
        if (!itemIds.has(id)) add("ERROR", w, `correct_order references unknown item "${id}"`);
      }
      if ((t.correct_order ?? []).length !== itemIds.size) {
        add("ERROR", w, "correct_order does not cover every item exactly once");
      }
    }
    if (t.type === "matching") {
      const ids = (t.pairs ?? []).map(p => p.id);
      if (new Set(ids).size !== ids.length) add("ERROR", w, "duplicate pair ids");
    }
    // the log rules that kept getting violated in scenarios
    const ev = t.event;
    if (ev?.raw) {
      // A single-observation DEVICE log (Windows Security, Sysmon, an EDR
      // process/DNS event, a cloud audit log, a proxy transaction) records one
      // action and cannot carry a windowed aggregate. A SIEM correlation rule
      // (Wazuh, Sentinel, QRadar…) or a SOAR case record genuinely can — that
      // synthesis is its whole job. Only flag the former.
      const AGGREGATING_SOURCES = new Set(["siem", "soar", "threat_intel"]);
      const aggregatesAreLegitimate = AGGREGATING_SOURCES.has(ev.source);
      for (const [k, v] of Object.entries(ev.raw)) {
        if (/\.Description$/.test(k)) {
          add("ERROR", w, `raw field "${k}" — that key does not exist in the Windows schema and always hides a hint`);
        }
        if (/^(pass_the_hash|hash_mismatch|is_malicious)$/.test(k) ||
            /^baseline\.|_per_minute$|_per_sec$|^time_since_|^ml\.score$/.test(k)) {
          add("ERROR", w, `raw field "${k}" states a conclusion the student should derive`);
        }
        if (!aggregatesAreLegitimate && /_last_\d+[a-z]*$|_count$|_breakdown/.test(k)) {
          // A single Windows/EDR/cloud-audit log entry records one action, not
          // an aggregation window. The Kerberos room shipped exactly this
          // (tgs_requests_last_180s on a raw 4769) and it wasn't caught until a
          // manual spot-check found it — it is not limited to that one room.
          add("ERROR", w, `raw field "${k}" is a windowed aggregate on a single-observation source (source="${ev.source}") — a device log doesn't emit this; state it in the task's context instead, or re-source the event as a SIEM/SOAR record if the aggregation is the point`);
        }
        // A field literally named for a party-not-supported-by-the-event, e.g.
        // "RequestorName" invented alongside a real "TargetUserName" on a 4769,
        // where TargetUserName already IS the requester. Not general enough to
        // regex reliably — flagged as a warning to prompt a manual look.
        if (/^winlog\.event_data\.(Requestor|Requester)Name$/.test(k)) {
          add("WARN", w, `"${k}" — verify this field actually exists on the event; Windows 4768/4769 do not carry a separate requestor-name field`);
        }
        if (typeof v === "string" && /\b(indicates?|consistent with|suspicious|lateral movement)\b/i.test(v) && k.endsWith("Description")) {
          add("ERROR", w, `raw field "${k}" reads like analysis`);
        }
      }
    }
    for (const d of DEPRECATED) {
      if (JSON.stringify(t).includes(d)) add("ERROR", w, `cites deprecated ATT&CK ID ${d}`);
    }
  }
}

// ── Coverage: is what we examine actually taught? ──────────────────────────
const practised = new Map();
for (const def of SCENARIOS) {
  let b; try { b = def.build(); } catch { continue; }
  for (const e of b.events ?? []) {
    if (e.mitre_technique) practised.set(e.mitre_technique, (practised.get(e.mitre_technique) ?? 0) + 1);
  }
}
const taughtBlob = JSON.stringify(ROOMS).toLowerCase() + JSON.stringify(QUIZZES).toLowerCase();
const orphans = [...practised.entries()]
  .filter(([t]) => !taughtBlob.includes(t.toLowerCase()))
  .sort((a, b) => b[1] - a[1]);

// ── report ─────────────────────────────────────────────────────────────────
const errors = findings.filter(f => f.sev === "ERROR");
const warns = findings.filter(f => f.sev === "WARN");

console.log(`\n\x1b[1mContent gate\x1b[0m   ${ROOMS.length} rooms, ${QUIZZES.length} quizzes`);
console.log(`  errors ${errors.length}   warnings ${warns.length}`);
console.log(`  techniques practised in scenarios but taught nowhere: ${orphans.length}/${practised.size}\n`);

const show = list => {
  for (const f of list) console.log(`    ${f.where.padEnd(46)} ${f.msg}`);
  console.log();
};
if (errors.length) { console.log("\x1b[31mERRORS\x1b[0m"); show(errors); }
if (warns.length && process.argv.includes("--warnings")) { console.log("\x1b[33mWARNINGS\x1b[0m"); show(warns); }
else if (warns.length) console.log(`  (${warns.length} warnings — re-run with --warnings)\n`);

if (process.argv.includes("--coverage") && orphans.length) {
  console.log("\x1b[33mPRACTISED BUT NEVER TAUGHT\x1b[0m  (write a room or quiz that covers these)");
  for (const [t, n] of orphans.slice(0, 40)) console.log(`    ${String(n).padStart(2)}x  ${t}`);
  console.log();
}

if (errors.length) {
  console.log(`\x1b[31m  FAIL — ${errors.length} blocking content defect(s).\x1b[0m\n`);
  process.exit(1);
}
console.log("\x1b[32m  PASS — no blocking content defects.\x1b[0m\n");
