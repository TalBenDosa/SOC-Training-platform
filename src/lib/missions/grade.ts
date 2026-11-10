/**
 * Grades ONE step of a practical mission. Pure; runs on the server only (it
 * reads the answer fields that sanitize.ts strips). Called from
 * src/lib/rooms/grading.ts for task type "mission".
 *
 * Help ladder and XP (SPEC section 2, principle 5):
 *  - checks 1..3 that pass: full step XP, or 60% if the learner opened the
 *    second hint ("where to look"). The client reports hint use; it can only
 *    lower XP, never raise it.
 *  - after the 3rd wrong check the worked answer is released; a later pass still
 *    completes the step (it counts toward the room's pass gate) but pays 0 XP.
 *  - a query that does not run, or an empty answer, is NOT a check: it returns an
 *    error before an attempt is claimed (the submit route's dry run).
 */
import { gradeKql } from "./kqlCompare";
import { getDataset } from "./datasets";
import { iocKey, looseText, normalizeAs, parseNumber, parseUtc, splitList, detectIocType } from "./normalize";
import { HINT2_FACTOR, WORKED_AFTER_MISSES, type MissionField, type MissionTask, type ReportStep, type StepWithXp, type IocType } from "./types";
import { buildSample, extractStrings } from "./yara/samples";
import { compileYara, scanYara } from "./yara";
import { matchSigma, parseSigma } from "./sigma";

export type StepGrade =
  | { ok: true; correct: boolean; xpEarned: number; reveal: Record<string, unknown> }
  | { ok: false; error: string; status: number };

const MAX_TEXT = 20_000;

function fail(error: string, status = 422): StepGrade { return { ok: false, error, status }; }

// ─── Typed fields ─────────────────────────────────────────────────────────────

function fieldCorrect(f: MissionField, raw: string): boolean {
  if (f.format === "choice") return f.accept.includes(raw.trim());
  if (f.format === "int" || f.format === "number") {
    const n = parseNumber(raw);
    if (n === null) return false;
    return f.accept.some(a => { const want = parseNumber(a); return want !== null && Math.abs(n - want) <= (f.tolerance ?? 0); });
  }
  if (f.format === "utc") {
    const got = parseUtc(raw);
    if (!got) return false;
    const tol = f.tolerance ?? 0;
    return f.accept.some(a => {
      const want = parseUtc(a);
      if (!want) return false;
      if (want.kind === got.kind) return Math.abs(want.minutes - got.minutes) <= tol;
      // A bare time against a date-time: compare the time of day (the case's day is fixed), wrapping at midnight.
      const d = Math.abs((((want.minutes - got.minutes) % 1440) + 1440) % 1440);
      return Math.min(d, 1440 - d) <= tol;
    });
  }
  if (f.format === "set") {
    const norm = (s: string) => normalizeAs(f.item ?? "text", s);
    const got = new Set(splitList(raw).map(norm));
    const want = new Set(f.accept.map(norm));
    return got.size === want.size && [...want].every(v => got.has(v));
  }
  if (f.format === "text") {
    const g = looseText(raw);
    return f.accept.some(a => a.startsWith("re:") ? safeRe(a.slice(3)).test(raw.trim()) : looseText(a) === g);
  }
  const g = normalizeAs(f.format, raw);
  return f.accept.some(a => normalizeAs(f.format as Exclude<MissionField["format"], "set">, a) === g);
}

function safeRe(p: string): RegExp {
  try { return new RegExp(p, "i"); } catch { return /$^/; }
}

// ─── Report checklist ─────────────────────────────────────────────────────────

function matches(pattern: string, text: string): boolean {
  if (pattern.startsWith("re:")) return safeRe(pattern.slice(3)).test(text);
  const norm = (s: string) => s.toLowerCase().replace(/,(?=\d{3}\b)/g, "").replace(/\s+/g, " ");
  return norm(text).includes(norm(pattern));
}

function gradeReport(step: ReportStep, slots: Record<string, unknown>) {
  const perSlot = step.slots.map(s => {
    const text = typeof slots[s.id] === "string" ? (slots[s.id] as string).slice(0, MAX_TEXT) : "";
    const words = text.trim().split(/\s+/).filter(Boolean).length;
    const missing = s.checks.filter(c => !c.anyOf.some(p => matches(p, text))).map(c => c.label);
    const flagged = (s.forbidden ?? []).filter(f => matches(f.pattern, text)).map(f => f.say);
    const tooLong = words > s.maxWords;
    return { id: s.id, label: s.label, words, missing, flagged, tooLong, ok: !!text.trim() && missing.length === 0 && flagged.length === 0 && !tooLong };
  });
  return perSlot;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- the answer shape depends on the step kind and is narrowed per case
export function gradeMissionStep(task: MissionTask, stepIndex: number, answer: any, attemptNo: number, hintsUsed: number): StepGrade {
  const step = task.steps[stepIndex] as StepWithXp | undefined;
  if (!step) return fail("Unknown step.", 404);
  if (!answer || typeof answer !== "object") return fail("answer (object) is required.", 400);

  let correct = false;
  const reveal: Record<string, unknown> = {};

  switch (step.kind) {
    case "kql": {
      const query = typeof answer.query === "string" ? answer.query : "";
      if (!query.trim()) return fail("Write a query first.", 400);
      if (query.length > MAX_TEXT) return fail("That query is too long.", 400);
      const ds = task.dataset ? getDataset(task.dataset) : null;
      if (!ds) return fail("This mission has no data.", 500);
      const v = gradeKql(step.answer, query, ds.visible, ds.shadow);
      if (v.error) return fail(`Your query did not run: ${v.error.message} (line ${v.error.line}). Fix it and run it before you check.`, 422);
      correct = v.pass;
      reveal.feedback = v.feedback;
      if (v.overfit) reveal.overfit = true;
      break;
    }

    case "fields": {
      const values = answer.values && typeof answer.values === "object" ? answer.values as Record<string, unknown> : null;
      if (!values) return fail("values (object) is required.", 400);
      if (step.fields.every(f => typeof values[f.id] !== "string" || !(values[f.id] as string).trim())) return fail("Fill in at least one field.", 400);
      const per = step.fields.map(f => {
        const raw = typeof values[f.id] === "string" ? (values[f.id] as string).slice(0, 2000) : "";
        const ok = !!raw.trim() && fieldCorrect(f, raw);
        const trap = ok ? undefined : f.traps?.find(t => looseText(t.value) === looseText(raw) || normalizeAs("ip", t.value) === normalizeAs("ip", raw));
        return { id: f.id, ok, say: ok ? undefined : (trap?.say ?? f.coach) };
      });
      correct = per.every(p => p.ok);
      reveal.fields = per;
      break;
    }

    case "iocs": {
      const rows = Array.isArray(answer.iocs) ? answer.iocs.slice(0, 60) : null;
      if (!rows || rows.length === 0) return fail("Add indicators to the notebook first.", 400);
      const typed: { type: IocType; key: string; raw: string }[] = [];
      for (const r of rows) {
        const raw = typeof r?.value === "string" ? r.value.slice(0, 2048) : "";
        if (!raw.trim()) continue;
        const type = (typeof r?.type === "string" ? r.type : detectIocType(raw)) as IocType | null;
        if (!type) continue;
        typed.push({ type, key: iocKey(type, raw), raw });
      }
      const keysOf = (value: string, type?: IocType) => {
        const t = type ?? detectIocType(value);
        return t ? iocKey(t, value) : value.trim().toLowerCase();
      };
      const have = new Set(typed.map(t => t.key));
      const found = step.expect.filter(e => have.has(keysOf(e.value, e.type)));
      const missing = step.expect.filter(e => !have.has(keysOf(e.value, e.type))).map(e => e.label);
      const flagged = step.forbidden.filter(f => have.has(keysOf(f.value))).map(f => ({ value: typed.find(t => t.key === keysOf(f.value))?.raw ?? f.value, say: f.say }));
      correct = missing.length === 0 && flagged.length === 0;
      reveal.iocs = { found: found.length, total: step.expect.length, missing, flagged };
      break;
    }

    case "strings": {
      const picks = Array.isArray(answer.picks) ? answer.picks.filter((p: unknown) => typeof p === "string").slice(0, 40) as string[] : null;
      if (!picks || picks.length === 0) return fail("Pick at least one string.", 400);
      const samples = task.samples ?? [];
      const sample = samples[step.sample];
      if (!sample) return fail("This mission has no sample.", 500);
      const counts = stringCorpusCounts(task);
      const sampleStrings = new Set(extractStrings(buildSample(sample.spec).bytes).map(s => s.value));
      const per = picks.map(p => {
        const c = counts.get(p);
        const inSample = sampleStrings.has(p);
        const ok = inSample && !!c && c.good === 0 && c.bad >= step.minBad;
        return { value: p, ok, good: c?.good ?? 0, bad: c?.bad ?? 0, inSample };
      });
      const goodPicks = per.filter(p => p.ok).length;
      correct = goodPicks >= step.minPicks && per.every(p => p.ok);
      reveal.picks = per;
      reveal.need = step.minPicks;
      break;
    }

    case "rule": {
      const source = typeof answer.source === "string" ? answer.source : "";
      if (!source.trim()) return fail("Write the rule first.", 400);
      if (source.length > 64_000) return fail("That rule is too long.", 400);
      if (step.language === "yara") {
        const compiled = compileYara(source);
        if (!compiled.ok) return fail(`Your rule did not compile: line ${compiled.error.line}: ${compiled.error.message}`, 422);
        const visible = task.samples ?? [];
        const hidden = step.hidden.samples ?? [];
        const run = (s: { label: "bad" | "good"; name: string; note?: string; spec: Parameters<typeof buildSample>[0] }) => {
          const built = buildSample(s.spec);
          return { name: s.name, label: s.label, note: s.note, matched: scanYara(compiled.rules, built.bytes, built.filesize).matched };
        };
        const vis = visible.map(run);
        const hid = hidden.map(run);
        const wrong = (r: { label: string; matched: boolean }) => (r.label === "bad") !== r.matched;
        correct = !vis.some(wrong) && !hid.some(wrong);
        reveal.rule = {
          visibleWrong: vis.filter(wrong).map(r => r.name),
          hiddenMissed: hid.filter(r => r.label === "bad" && !r.matched).map(r => ({ name: r.name, note: r.note })),
          hiddenFalse: hid.filter(r => r.label === "good" && r.matched).map(r => ({ name: r.name, note: r.note })),
          hiddenTotal: hid.length,
        };
      } else {
        const parsed = parseSigma(source);
        if (!parsed.ok) return fail(`Your rule did not parse: line ${parsed.error.line}: ${parsed.error.message}`, 422);
        const run = (e: { id: string; label: "bad" | "good"; note?: string; fields: Record<string, unknown> }) => ({ id: e.id, label: e.label, note: e.note, matched: matchSigma(parsed.rule, e.fields).matched });
        const vis = (task.events ?? []).map(run);
        const hid = (step.hidden.events ?? []).map(run);
        const wrong = (r: { label: string; matched: boolean }) => (r.label === "bad") !== r.matched;
        correct = !vis.some(wrong) && !hid.some(wrong);
        reveal.rule = {
          visibleWrong: vis.filter(wrong).map(r => r.id),
          hiddenMissed: hid.filter(r => r.label === "bad" && !r.matched).map(r => ({ name: r.id, note: r.note })),
          hiddenFalse: hid.filter(r => r.label === "good" && r.matched).map(r => ({ name: r.id, note: r.note })),
          hiddenTotal: hid.length,
          warnings: parsed.warnings,
        };
      }
      break;
    }

    case "report": {
      const slots = answer.slots && typeof answer.slots === "object" ? answer.slots as Record<string, unknown> : null;
      if (!slots || step.slots.every(s => typeof slots[s.id] !== "string" || !(slots[s.id] as string).trim())) return fail("Write the finding first.", 400);
      const per = gradeReport(step, slots);
      correct = per.every(p => p.ok);
      reveal.slots = per;
      break;
    }
  }

  const misses = correct ? attemptNo - 1 : attemptNo;
  const workedOut = misses >= WORKED_AFTER_MISSES;
  let xpEarned = 0;
  if (correct) {
    // The attempt that passes after the worked answer was shown pays nothing.
    const sawWorked = attemptNo - 1 >= WORKED_AFTER_MISSES;
    xpEarned = sawWorked ? 0 : Math.round(step.xp * (hintsUsed >= 2 ? HINT2_FACTOR : 1));
  }
  if (correct || workedOut) {
    reveal.worked = step.worked;
    reveal.debrief = step.debrief;
  }
  reveal.misses = misses;
  return { ok: true, correct, xpEarned, reveal };
}

/** For every string in the mission's samples: in how many bad and good files (visible and hidden) it appears. */
export function stringCorpusCounts(task: MissionTask): Map<string, { bad: number; good: number }> {
  const all = [...(task.samples ?? [])];
  for (const s of task.steps) if (s.kind === "rule") all.push(...(s.hidden.samples ?? []));
  const out = new Map<string, { bad: number; good: number }>();
  for (const s of all) {
    const seen = new Set(extractStrings(buildSample(s.spec).bytes).map(x => x.value));
    for (const v of seen) {
      const c = out.get(v) ?? { bad: 0, good: 0 };
      if (s.label === "bad") c.bad++; else c.good++;
      out.set(v, c);
    }
  }
  return out;
}
