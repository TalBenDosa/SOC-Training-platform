import "server-only";
/**
 * Turns a stored report (target_kind + target_id + the context the client sent) into a
 * location an admin can read at a glance: what kind of content, the breadcrumb, the exact
 * step, what the learner had on screen, and a link to open it. Server-side because the room
 * and quiz texts live in server-only data; nothing answer-bearing is returned (no correct
 * answers, no explanations), only what the learner was shown.
 *
 * Older reports carry only the client's context (room / task_index / task_type), so every
 * branch falls back to the context when the content cannot be found (e.g. an org-authored room).
 */
import { ROOMS } from "@/data/rooms";
import { findLesson } from "@/lib/lessons/paths";
import { getQuiz } from "@/lib/quizzes/data";
import { SCENARIOS_META } from "@/lib/sim/scenariosMeta";
import { KIND_LABEL, TASK_TYPE_LABEL, browserSummary, taskShown } from "./labels";

export interface ReportLocationView {
  kind: string;            // lesson | room_task | quiz | scenario | dashboard | technical
  kindLabel: string;
  crumbs: string[];        // e.g. ["Learning room", "Encoding, Encryption & Hashing"]
  step?: string;           // e.g. "Task 5 of 16 · Analyst verdict"
  shown?: string;          // the question / page title / log line the learner saw
  href?: string;           // where to open it
  details: { label: string; value: string }[]; // technical extras, shown collapsed
}

/** `{pathSlug}--{lessonSlug}` (the lessonKey); same split as lessonContent.parseLessonSlug, without its server cache. */
function parseLessonKey(raw: string): { pathSlug: string; lessonSlug: string } | null {
  const sep = raw.indexOf("--");
  return sep === -1 ? null : { pathSlug: raw.slice(0, sep), lessonSlug: raw.slice(sep + 2) };
}

const crumbsOf = (where: string | undefined) => (where ? where.split(/\s*›\s*/).filter(Boolean) : []);

export function resolveLocation(kind: string, targetId: string, ctx: Record<string, string> = {}): ReportLocationView {
  const technical = ctx.category === "technical" || targetId === "technical" || kind === "other";
  const details: { label: string; value: string }[] = [];
  if (ctx.page) details.push({ label: "Page", value: ctx.page });
  const browser = browserSummary(ctx.userAgent);
  if (browser) details.push({ label: "Browser", value: browser });
  if (ctx.viewport) details.push({ label: "Screen", value: ctx.viewport });

  if (technical) {
    return {
      kind: "technical", kindLabel: "Technical problem",
      crumbs: ctx.where ? crumbsOf(ctx.where) : [ctx.page ? `Page ${ctx.page.split("?")[0]}` : "Unknown page"],
      step: ctx.step, shown: ctx.shown, href: ctx.page, details,
    };
  }

  switch (kind) {
    case "room_task": {
      const [roomId, taskId] = targetId.split(":");
      const room = ROOMS.find(r => r.id === roomId);
      const idx = room ? room.tasks.findIndex(t => t.id === taskId) : -1;
      const task = room && idx >= 0 ? room.tasks[idx] : undefined;
      details.push({ label: "Room id", value: roomId }, ...(taskId ? [{ label: "Task id", value: taskId }] : []));
      return {
        kind, kindLabel: KIND_LABEL.room_task,
        crumbs: ["Learning room", room?.title ?? ctx.room ?? roomId],
        step: task && room
          ? `Task ${idx + 1} of ${room.tasks.length} · ${TASK_TYPE_LABEL[task.type] ?? task.type}`
          : ctx.step ?? (ctx.task_index ? `Task ${ctx.task_index}${ctx.task_type ? ` · ${TASK_TYPE_LABEL[ctx.task_type] ?? ctx.task_type}` : ""}` : undefined),
        shown: taskShown(task as unknown as Record<string, unknown>) ?? ctx.shown,
        href: `/rooms/${roomId}`,
        details,
      };
    }
    case "lesson": {
      const parsed = parseLessonKey(targetId);
      const found = parsed ? findLesson(parsed.pathSlug, parsed.lessonSlug) : null;
      return {
        kind, kindLabel: KIND_LABEL.lesson,
        crumbs: found ? ["Learning path", found.path.title, found.module.title, found.lesson.title] : crumbsOf(ctx.where),
        step: ctx.step, shown: ctx.shown,
        href: parsed ? `/learn/${parsed.pathSlug}/${parsed.lessonSlug}` : ctx.page,
        details,
      };
    }
    case "quiz": {
      const [slug, questionId] = targetId.split(":");
      const quiz = getQuiz(slug);
      const qIdx = quiz && questionId ? quiz.questions.findIndex(q => q.id === questionId) : -1;
      return {
        kind, kindLabel: KIND_LABEL.quiz,
        crumbs: ["Quiz", quiz?.title ?? slug],
        step: quiz && qIdx >= 0 ? `Question ${qIdx + 1} of ${quiz.questions.length}` : ctx.step,
        shown: quiz && qIdx >= 0 ? quiz.questions[qIdx].question : ctx.shown,
        href: `/quizzes/${slug}`,
        details,
      };
    }
    case "scenario": {
      const meta = SCENARIOS_META.find(s => s.slug === targetId);
      return {
        kind, kindLabel: KIND_LABEL.scenario,
        crumbs: ["Scenario", meta?.title ?? targetId],
        step: ctx.step, shown: ctx.shown,
        href: `/scenarios/${targetId}`,
        details,
      };
    }
    case "dashboard": {
      details.push({ label: "Event id", value: targetId });
      return {
        kind, kindLabel: KIND_LABEL.dashboard,
        crumbs: ctx.where ? crumbsOf(ctx.where) : ["Live SOC feed"],
        step: ctx.step, shown: ctx.shown, href: "/dashboard",
        details,
      };
    }
    default:
      return { kind, kindLabel: KIND_LABEL[kind] ?? kind, crumbs: ctx.where ? crumbsOf(ctx.where) : [targetId], step: ctx.step, shown: ctx.shown, href: ctx.page, details };
  }
}
