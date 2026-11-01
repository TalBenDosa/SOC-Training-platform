/**
 * GET /api/me/mistakes — the learner's own mistakes, grouped by skill area, then source
 * (room, quiz, lesson check, scenario), then question.
 *
 * REVEAL RULE: a right answer is returned only when the grader itself has already shown
 * it to this learner (lib/org/mistakeView answerRevealed, policy "self"): never for an
 * unsolved flag, and for multiple-choice / analyst-verdict tasks only after the second try
 * or once solved. Quiz, lesson-check and scenario questions reveal on grading, so their
 * answers are shown. Built server-side; the answer keys never ship in client code.
 *
 * Scope: the caller's own rows in their current organisation only (iron rule).
 */
import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { fetchAll } from "@/lib/plans/server";
import { groupItems } from "@/lib/org/firstTry";
import { buildMistakeGroups, type StoredAttempt } from "@/lib/org/mistakeView";
import { areaOf, QUIZ_TITLE, SCENARIO_TITLE } from "@/lib/skills/contentArea";
import { SKILL_AREAS, SKILL_LABEL, type SkillArea } from "@/lib/skills/taxonomy";
import { resolveGradableQuiz } from "@/lib/quizzes/resolve";
import { resolveScenarioBundle } from "@/lib/scenarios/resolve";
import { PATH_LESSON_CONTENT } from "@/data/pathLessonContent";
import { lessonTitle } from "@/lib/progress/selfView";
import { loadSelfScope, scopeOrg, type FirstAnswerFull } from "@/lib/progress/scope";
import { ROOMS_META } from "@/data/roomsMeta";

export const maxDuration = 30;

export interface SelfMistake {
  key: string;
  position: string | null;
  typeLabel: string;
  prompt: string | null;
  chosen: string | null;
  /** Null while the answer has not been revealed to the learner. */
  correct: string | null;
  explanation: string | null;
  tries: number | null;
  solved: boolean | null;
  triesToSolve: number | null;
  latencyMs: number | null;
  at: string | null;
  verdictError: "fn" | "fp" | null;
}
export interface SelfMistakeSource {
  kind: "room" | "quiz" | "lesson" | "scenario";
  id: string; title: string; href: string | null;
  items: number; firstTryCorrect: number;
  mistakes: SelfMistake[];
}
export interface SelfMistakesPayload {
  areas: { area: SkillArea; label: string; mistakes: number; unsolved: number; sources: SelfMistakeSource[] }[];
  /** Revealed analyst-verdict errors: real attacks called benign vs benign events called attacks. */
  pattern: { fn: number; fp: number };
  /** Revealed analyst-verdict tasks where a real attack was called benign on the first try. */
  missedAttacks: { roomId: string; roomTitle: string; prompt: string | null; at: string | null; href: string }[];
}

const ROOM_CATEGORY: Record<string, string> = Object.fromEntries(ROOMS_META.map(r => [r.id, r.category]));
const cut = (s: unknown, n = 400): string | null => {
  if (s === undefined || s === null || s === "") return null;
  const t = String(s).replace(/\s+/g, " ").trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
};

export async function GET() {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Sign in to see your mistakes.", guest: true }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Progress storage isn't configured." }, { status: 503 });
  const scope = await loadSelfScope(admin, user);

  let attempts: StoredAttempt[];
  try {
    attempts = await fetchAll<StoredAttempt>((from, to) => scopeOrg(admin.from("task_attempts")
      .select("room_id, task_id, task_type, question_index, attempt_no, correct, submitted, latency_ms, created_at")
      .eq("user_id", user.id), scope)
      .order("created_at", { ascending: true }).order("id", { ascending: true })
      .range(from, to) as unknown as PromiseLike<{ data: StoredAttempt[] | null; error: { message: string } | null }>, "me:mistakes", 20_000);
  } catch (e) {
    console.error("[me/mistakes] attempts read failed:", e instanceof Error ? e.message : e);
    return NextResponse.json({ error: "Couldn't load your answers right now. Please try again." }, { status: 500 });
  }
  const items = groupItems(attempts);
  // org-authored rooms resolve through the learner's org; no org → built-ins only.
  const groups = await buildMistakeGroups(items, scope.orgId ?? "", id => ROOM_CATEGORY[id] ?? null, "self");

  const byArea = new Map<SkillArea, SelfMistakeSource[]>();
  const push = (area: SkillArea, src: SelfMistakeSource) => { const l = byArea.get(area) ?? []; l.push(src); byArea.set(area, l); };
  const pattern = { fn: 0, fp: 0 };
  const missedAttacks: SelfMistakesPayload["missedAttacks"] = [];

  for (const g of groups) {
    const href = `/rooms/${encodeURIComponent(g.room_id)}`;
    for (const m of g.mistakes) {
      if (m.verdict_error === "fn") { pattern.fn++; missedAttacks.push({ roomId: g.room_id, roomTitle: g.room_title, prompt: m.prompt, at: m.last_at, href }); }
      if (m.verdict_error === "fp") pattern.fp++;
    }
    push(areaOf("room", g.room_id), {
      kind: "room", id: g.room_id, title: g.room_title, href, items: g.items, firstTryCorrect: g.first_try_correct,
      mistakes: g.mistakes.map(m => ({
        key: m.key, position: m.task_position, typeLabel: m.type_label, prompt: m.prompt, chosen: m.chosen, correct: m.correct,
        explanation: m.explanation, tries: m.tries, solved: m.solved, triesToSolve: m.tries_to_solve, latencyMs: m.latency_ms,
        at: m.last_at, verdictError: m.verdict_error ?? null,
      })),
    });
  }

  // Quizzes, lesson checks and scenario questions: the FIRST answer per question (0078).
  const firsts = await scope.readFirsts(true);
  const bySource = new Map<string, FirstAnswerFull[]>();
  for (const f of firsts) { const k = `${f.kind}|${f.content_id}`; const l = bySource.get(k) ?? []; l.push(f); bySource.set(k, l); }
  await Promise.all([...bySource.entries()].map(async ([k, rows]) => {
    const wrong = rows.filter(r => !r.correct);
    if (wrong.length === 0) return;
    const sep = k.indexOf("|"); const kind = k.slice(0, sep) as FirstAnswerFull["kind"]; const id = k.slice(sep + 1);
    const ok = rows.length - wrong.length;
    try {
      if (kind === "quiz") {
        const quiz = await resolveGradableQuiz(id, scope.orgId);
        push(areaOf("quiz", id), {
          kind, id, title: quiz?.title ?? QUIZ_TITLE[id] ?? id, href: `/quizzes/${encodeURIComponent(id)}`, items: rows.length, firstTryCorrect: ok,
          mistakes: wrong.map(r => {
            const q = quiz?.questions.find(x => x.id === r.question_id);
            const idx = quiz ? quiz.questions.findIndex(x => x.id === r.question_id) : -1;
            return firstMistake(r, idx >= 0 && quiz ? `Question ${idx + 1} of ${quiz.questions.length}` : null, "Quiz question",
              q?.question, typeof r.answer === "number" ? q?.options[r.answer] : null, q ? q.options[q.answer] : null, q?.explanation);
          }),
        });
      } else if (kind === "lesson") {
        const quiz = PATH_LESSON_CONTENT[id]?.quiz ?? [];
        push(areaOf("lesson", id), {
          kind, id, title: lessonTitle(id), href: lessonHref(id), items: rows.length, firstTryCorrect: ok,
          mistakes: wrong.map(r => {
            const qi = Number(r.question_id); const q = Number.isInteger(qi) ? quiz[qi] : undefined;
            const label = (v: unknown) => q?.options.find(o => o.value === v)?.label ?? (typeof v === "string" ? v : null);
            return firstMistake(r, q ? `Question ${qi + 1} of ${quiz.length}` : null, "Knowledge check", q?.question, label(r.answer), q ? label(q.answer) : null, q?.explanation);
          }),
        });
      } else {
        const bundle = await resolveScenarioBundle(id, scope.orgId).catch(() => null);
        push(areaOf("scenario", id), {
          kind, id, title: bundle?.title ?? SCENARIO_TITLE[id] ?? id, href: `/scenarios/${encodeURIComponent(id)}`, items: rows.length, firstTryCorrect: ok,
          mistakes: wrong.map(r => {
            const idx = bundle ? bundle.questions.findIndex(x => x.id === r.question_id) : -1;
            const q = idx >= 0 ? bundle!.questions[idx] : undefined;
            const label = (v: unknown): string | null => {
              if (Array.isArray(v)) return v.map(x => label(x)).filter(Boolean).join(", ") || null;
              return q?.options?.find(o => o.value === v)?.label ?? (typeof v === "string" ? v : null);
            };
            return firstMistake(r, q ? `Question ${idx + 1} of ${bundle!.questions.length}` : null, "Scenario question", q?.prompt, label(r.answer), q ? label(q.answer) : null, q?.explanation);
          }),
        });
      }
    } catch (e) {
      console.error(`[me/mistakes] ${k} content load failed:`, e instanceof Error ? e.message : e);
    }
  }));

  const areas = SKILL_AREAS.map(a => {
    const sources = (byArea.get(a.id) ?? []).sort((x, y) => y.mistakes.length - x.mistakes.length || x.title.localeCompare(y.title));
    const all = sources.flatMap(s => s.mistakes);
    return { area: a.id, label: SKILL_LABEL[a.id], mistakes: all.length, unsolved: all.filter(m => m.solved === false).length, sources };
  }).filter(a => a.mistakes > 0).sort((x, y) => y.mistakes - x.mistakes);

  const payload: SelfMistakesPayload = {
    areas, pattern,
    missedAttacks: missedAttacks.sort((a, b) => Date.parse(b.at ?? "0") - Date.parse(a.at ?? "0")).slice(0, 30),
  };
  return NextResponse.json(payload, { headers: { "Cache-Control": "private, no-store" } });
}

function firstMistake(r: FirstAnswerFull, position: string | null, typeLabel: string, prompt: unknown, chosen: unknown, correct: unknown, explanation: unknown): SelfMistake {
  return {
    key: `${r.kind}|${r.content_id}|${r.question_id}`, position, typeLabel,
    prompt: cut(prompt), chosen: cut(chosen), correct: cut(correct), explanation: cut(explanation),
    // Only the first answer is kept for these, so later tries are unknown.
    tries: null, solved: null, triesToSolve: null, latencyMs: null, at: r.created_at, verdictError: null,
  };
}

function lessonHref(key: string): string | null {
  const sep = key.indexOf("--");
  return sep > 0 ? `/learn/${encodeURIComponent(key.slice(0, sep))}/${encodeURIComponent(key.slice(sep + 2))}` : null;
}
