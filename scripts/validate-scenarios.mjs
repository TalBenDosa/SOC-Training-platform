#!/usr/bin/env node
/**
 * Scenario content gate.
 *
 * Three independent expert reviews of the shipped scenarios found the same
 * defects over and over: attack chains that require privileges the timeline
 * never grants, raw logs containing the analyst's conclusion instead of an
 * observation, events that silently raise no alert, and questions whose correct
 * answer is simply the longest option. Each check below exists because that
 * defect was found in real content, and each one is cheap to run.
 *
 *   npm run validate:scenarios
 */

import { pathToFileURL } from "node:url";
import path from "node:path";

const ROOT = process.cwd();
const { SCENARIOS } = await import(
  pathToFileURL(path.join(ROOT, "src/lib/sim/scenarios.ts")).href
);

const findings = [];
const add = (sev, slug, where, msg) => findings.push({ sev, slug, where, msg });

/** Fields that state a conclusion rather than record an observation. */
const CONCLUSION_KEYS = [
  /\.Description$/,
  /^pass_the_hash$/, /_hash_mismatch$/, /^hash_mismatch$/,
  /forged/i, /^kerberos\.ticket\./,
  /^baseline\./, /^behavior\.(baseline|deviation)/,
  /^ueba\.(deviation_factor|hr_risk_flag)/,
  /^data_breach\./,
  /_per_minute$/, /_per_sec$/, /_rate_/,
  /^time_since_/, /^hours_(after|since)_/, /_delay_seconds$/,
  /^ml\.score$/, /quarantine_threshold/,
  /^first_time_country$/, /^user\.is_local_admin$/,
];

/** Prose that gives the analysis away when it appears inside a raw field. */
const CONCLUSION_TEXT =
  /\b(indicates?|consistent with|suspicious|crackable|lateral movement|forged|attacker using|possible credential|unusual time|bypasses|evades)\b/i;

const DEPRECATED_ATTACK = ["T1076", "T1086", "T1064", "T1035", "T1117", "T1055.999"];

for (const def of SCENARIOS) {
  let b;
  try {
    b = def.build();
  } catch (e) {
    add("ERROR", def.slug, "build()", String(e).slice(0, 120));
    continue;
  }
  const slug = def.slug;

  // ── 1. Every scenario must be gradeable ────────────────────────────────
  if (!b.questions || b.questions.length === 0) {
    add("ERROR", slug, "questions", "no questions — score computes as 0/0 and the scenario can never be passed");
  }

  // ── 1b. The briefing must not answer the exercise ──────────────────────
  // The analyst reconstructs the attack from the logs. Anything the ticket
  // states up front is work the student never does — the LockBit briefing named
  // the victim role, the lateral-movement protocol and the pre-encryption step,
  // which between them answered four of its five questions.
  if (!b.briefing) {
    add("ERROR", slug, "briefing", "no briefing — the full narrative would be shown before any log is read");
  } else {
    const brief = b.briefing.toLowerCase();
    if (b.briefing.length > 420) {
      add("WARN", slug, "briefing", `${b.briefing.length} chars — a ticket is terse; long briefings smuggle in findings`);
    }
    if (/\bT1\d{3}(\.\d{3})?\b/i.test(b.briefing)) {
      add("ERROR", slug, "briefing", "names an ATT&CK technique ID — that is the analyst's conclusion");
    }
    const TELLS = [
      "lateral movement", "pass-the-hash", "pass the hash", "privilege escalation",
      "exfiltrat", "patient zero", "kill chain", "killchain", "c2 ", "command and control",
      "shadow copies", "credential dump", "lsass", "kerberoast", "golden ticket",
      "web shell", "webshell", "uac bypass", "token theft", "session hijack",
    ];
    for (const t of TELLS) {
      if (brief.includes(t)) {
        add("ERROR", slug, "briefing", `states "${t}" — that is a finding the student should derive`);
        break;
      }
    }
    // A briefing that repeats a correct answer verbatim is the same defect.
    for (const q of b.questions ?? []) {
      const correct = Array.isArray(q.answer) ? q.answer : [q.answer];
      for (const o of q.options ?? []) {
        if (!correct.includes(o.value)) continue;
        const words = o.label.toLowerCase().split(/[^a-z0-9.]+/).filter(w => w.length > 6);
        const overlap = words.filter(w => brief.includes(w));
        if (words.length >= 3 && overlap.length >= Math.ceil(words.length * 0.6)) {
          add("ERROR", slug, `briefing/${q.id}`,
            `briefing overlaps the correct answer ("${o.label.slice(0, 50)}…")`);
        }
      }
    }
  }

  // ── 2. Every learning objective must be assessed somewhere ─────────────
  if ((b.learning_objectives ?? []).length > (b.questions ?? []).length + 1) {
    add("WARN", slug, "objectives",
      `${b.learning_objectives.length} objectives but only ${b.questions.length} questions — some objective is untested`);
  }

  for (const e of b.events ?? []) {
    const at = `${e.id}`;

    // ── 3. An event that declares a technique in raw must declare it on the
    //      event too, or eventsToAlerts silently drops it from the queue.
    if (e.raw?.["threat.technique.id"] && !e.mitre_technique) {
      add("ERROR", slug, at, "raw declares threat.technique.id but the event has no mitre_technique — this event raises no alert");
    }

    // ── 4. Raw logs record observations, not conclusions ───────────────────
    for (const [k, v] of Object.entries(e.raw ?? {})) {
      if (CONCLUSION_KEYS.some(re => re.test(k))) {
        add("ERROR", slug, at, `raw field "${k}" states a derived conclusion — belongs in the description, not the evidence`);
      }
      if (typeof v === "string" && v.length > 25 && CONCLUSION_TEXT.test(v)) {
        add("WARN", slug, at, `raw field "${k}" reads like analysis: "${v.slice(0, 60)}…"`);
      }
    }

    // ── 5. Deprecated ATT&CK IDs ───────────────────────────────────────────
    if (e.mitre_technique && DEPRECATED_ATTACK.includes(e.mitre_technique)) {
      add("ERROR", slug, at, `${e.mitre_technique} is deprecated in ATT&CK`);
    }
  }

  // ── 6. The privilege chain must be earned ───────────────────────────────
  // A process cannot run at higher integrity than its parent unless an
  // elevation happened. Track the highest integrity seen so far in time order;
  // a jump upward with no event in between is the "attacker just could" defect.
  // Only a jump *within one actor's* chain is suspect. A scenario may legitimately
  // open with something already elevated — a service account running at High, or a
  // daemon as root — so the first observation sets the baseline rather than being
  // measured against an assumed "low".
  const RANK = { low: 0, medium: 1, high: 2, system: 3 };
  const ordered = [...(b.events ?? [])].sort((a, c) => new Date(a.ts) - new Date(c.ts));
  const byUser = new Map();
  for (const e of ordered) {
    const lvl = e.process?.integrity;
    const who = e.process?.user;
    if (!lvl || !who || !(lvl in RANK)) continue;
    const r = RANK[lvl];
    const prev = byUser.get(who);
    if (prev && r > prev.rank + 1) {
      add("ERROR", slug, e.id,
        `${who} jumps ${prev.lvl} → ${lvl} with no escalation event between (previously ${prev.at})`);
    }
    if (!prev || r > prev.rank) byUser.set(who, { rank: r, lvl, at: e.id });
  }

  // The jump check above only sees *changes* in integrity. The defect that
  // actually shipped was different: a process sitting at medium performing an
  // action that medium cannot perform. Opening lsass.exe with PROCESS_ALL_ACCESS
  // needs SeDebugPrivilege; writing to ADMIN$/C$ or installing a service needs
  // local admin on the target. Those require an elevated token, full stop.
  const NEEDS_ELEVATION = [
    { re: /lsass/i,                         why: "reading lsass.exe memory requires SeDebugPrivilege" },
    { re: /comsvcs\.dll.*MiniDump/i,        why: "comsvcs MiniDump against lsass requires SeDebugPrivilege" },
    { re: /ADMIN\$|\bC\$/i,                 why: "writing to an administrative share requires local admin on the target" },
    { re: /PSEXESVC|sc\s+create|New-Service/i, why: "installing a service requires local admin" },
    { re: /vssadmin.*delete|wbadmin\s+delete/i, why: "deleting shadow copies requires an elevated token" },
    { re: /\/ru\s+SYSTEM/i,                 why: "creating a task that runs as SYSTEM requires local admin" },
    { re: /ntdsutil|ntds\.dit/i,            why: "extracting NTDS.dit requires SeBackupPrivilege at High or above" },
  ];
  for (const e of b.events ?? []) {
    const lvl = e.process?.integrity;
    if (!lvl || RANK[lvl] === undefined || RANK[lvl] >= RANK.high) continue;
    const text = `${e.process?.cmdline ?? ""} ${e.description ?? ""} ${JSON.stringify(e.raw ?? {})}`;
    for (const n of NEEDS_ELEVATION) {
      if (n.re.test(text)) {
        add("ERROR", slug, e.id,
          `process runs at ${lvl} integrity but ${n.why} — the chain must show the escalation`);
        break;
      }
    }
  }

  // ── 7. IOC hygiene ──────────────────────────────────────────────────────
  for (const i of b.iocs ?? []) {
    for (const t of i.tags ?? []) {
      if (/roasting|relay|poison|fatigue|exfil|pass-the|golden|kerberoast/i.test(t)) {
        add("WARN", slug, `ioc ${i.value.slice(0, 28)}`, `tag "${t}" names the technique the student must derive`);
      }
    }
    if (i.type === "sha256" && !/^[a-f0-9]{64}$/i.test(i.value)) {
      add("ERROR", slug, `ioc ${i.value.slice(0, 28)}`, "declared sha256 but the value is not a 64-hex hash");
    }
  }

  // ── 8. Questions must not be answerable by shape alone ──────────────────
  for (const q of b.questions ?? []) {
    const opts = q.options ?? [];
    if (opts.length < 2) continue;
    const correct = Array.isArray(q.answer) ? q.answer : [q.answer];
    const right = opts.filter(o => correct.includes(o.value));
    const wrong = opts.filter(o => !correct.includes(o.value));
    if (!wrong.length) {
      add("ERROR", slug, q.id, "every option is correct — the question cannot discriminate");
      continue;
    }
    const longestRight = Math.max(...right.map(o => o.label.length), 0);
    const longestWrong = Math.max(...wrong.map(o => o.label.length));
    if (longestRight > longestWrong * 1.8) {
      add("WARN", slug, q.id,
        `correct option is ${Math.round(longestRight / longestWrong * 100)}% the length of the longest distractor — answerable without reading`);
    }
    for (const o of opts) {
      const id = (o.label.match(/\bT1\d{3}(?:\.\d{3})?\b/) ?? [])[0];
      if (id && DEPRECATED_ATTACK.includes(id)) {
        add("ERROR", slug, q.id, `option cites deprecated ATT&CK ID ${id}`);
      }
    }
  }
}

// ── report ────────────────────────────────────────────────────────────────
const errors = findings.filter(f => f.sev === "ERROR");
const warns = findings.filter(f => f.sev === "WARN");

console.log(`\n\x1b[1mScenario content gate\x1b[0m   ${SCENARIOS.length} scenarios`);
console.log(`  errors ${errors.length}   warnings ${warns.length}\n`);

const show = list => {
  const bySlug = {};
  for (const f of list) (bySlug[f.slug] ??= []).push(f);
  for (const [slug, fs] of Object.entries(bySlug)) {
    console.log(`  \x1b[1m${slug}\x1b[0m`);
    for (const f of fs) console.log(`    ${f.where.padEnd(28)} ${f.msg}`);
    console.log();
  }
};

if (errors.length) { console.log("\x1b[31mERRORS\x1b[0m"); show(errors); }
if (warns.length && process.argv.includes("--warnings")) { console.log("\x1b[33mWARNINGS\x1b[0m"); show(warns); }
else if (warns.length) console.log(`  (${warns.length} warnings — re-run with --warnings to see them)\n`);

if (errors.length) {
  console.log(`\x1b[31m  FAIL — ${errors.length} blocking content defect(s).\x1b[0m\n`);
  process.exit(1);
}
console.log("\x1b[32m  PASS — no blocking content defects.\x1b[0m\n");
