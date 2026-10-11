import "server-only";
import { randomUUID } from "crypto";
import type { Room, RoomTask } from "@/data/rooms";

/**
 * Authored-room split/recombine (Phase 3 — migration 0043). Same two-projection
 * model as scenarios: content_rooms.content holds the CLIENT-SAFE room (meta +
 * tasks with answers stripped) and content_room_keys.answer_key holds the answer
 * material (in a table the browser cannot read). splitAuthoredRoom is the only
 * producer of both; recombineRoom rebuilds the full Room for the server-side
 * grader. Ids are namespaced `org-<org8>-…` so they never collide with a static
 * built-in room id.
 *
 * v1 supports the three non-telemetry task kinds that make a complete learning
 * room: reading (teach), question (multiple-choice test), flag (find-the-value).
 * The split/recombine is keyed by task id, so more kinds can be added later
 * without changing the storage shape.
 */

export interface AuthoredRoomInput {
  id?: string;
  title?: unknown;
  description?: unknown;
  difficulty?: unknown;
  category?: unknown;
  icon?: unknown;
  estimatedMinutes?: unknown;
  tasks?: unknown;
}

export type RoomSplitResult =
  | { ok: true; id: string; safeContent: Record<string, unknown>; answerKey: Record<string, unknown> }
  | { ok: false; error: string };

const str = (v: unknown, max: number) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const strArr = (v: unknown, max: number, cap = 8) =>
  Array.isArray(v) ? v.map(x => str(x, max)).filter(Boolean).slice(0, cap) : [];
const num = (v: unknown, def: number, min: number, maxV: number) => {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? Math.min(maxV, Math.max(min, Math.round(n))) : def;
};
function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "room";
}
function newId(orgId: string, title: string): string {
  const ns = orgId.replace(/-/g, "").slice(0, 8);
  return `org-${ns}-${slugify(title)}-${randomUUID().slice(0, 4)}`;
}
export function isOrgRoomIdFor(id: string, orgId: string): boolean {
  const ns = orgId.replace(/-/g, "").slice(0, 8);
  return typeof id === "string" && id.startsWith(`org-${ns}-`);
}

const DIFFS = ["beginner", "intermediate", "advanced"];

export function splitAuthoredRoom(orgId: string, input: AuthoredRoomInput): RoomSplitResult {
  const title = str(input.title, 160);
  if (!title) return { ok: false, error: "Give the room a title." };
  const description = str(input.description, 600);
  if (!description) return { ok: false, error: "Write a short description for the room." };

  const id = input.id && isOrgRoomIdFor(str(input.id, 120), orgId) ? str(input.id, 120) : newId(orgId, title);
  const difficulty = DIFFS.includes(str(input.difficulty, 20)) ? str(input.difficulty, 20) : "beginner";

  const rawTasks = Array.isArray(input.tasks) ? input.tasks : [];
  const safeTasks: Record<string, unknown>[] = [];
  const keyTasks: Record<string, Record<string, unknown>> = {};
  let totalXp = 0;

  rawTasks.forEach((t, i) => {
    const o = (t ?? {}) as Record<string, unknown>;
    const kind = str(o.kind, 30);
    const tid = `${id}-t${i + 1}`;

    if (kind === "reading") {
      const heading = str(o.heading, 200);
      const content = str(o.content, 12000);
      if (!heading || !content) return;
      const xp = num(o.xp, 5, 0, 100);
      const safe: Record<string, unknown> = { type: "reading", id: tid, heading, content, xp };
      const code = str(o.codeExample, 4000);
      if (code) safe.codeExample = code;
      // Optional ungraded checkpoint — split its answer/explanation out.
      const cp = (o.checkpoint ?? null) as Record<string, unknown> | null;
      const cpQ = cp ? str(cp.question, 400) : "";
      const cpOpts = cp ? strArr(cp.options, 300, 6) : [];
      if (cpQ && cpOpts.length >= 2) {
        safe.checkpoint = { question: cpQ, options: cpOpts };
        keyTasks[tid] = { checkpoint: { answer: num(cp!.correct, 0, 0, cpOpts.length - 1), explanation: str(cp!.explanation, 800) } };
      }
      safeTasks.push(safe);
      totalXp += xp;
      return;
    }

    if (kind === "question") {
      const question = str(o.question, 600);
      const options = strArr(o.options, 400, 6);
      if (!question || options.length < 2) return;
      const xp = num(o.xp, 25, 0, 200);
      safeTasks.push({ type: "question", id: tid, question, options, xp });
      keyTasks[tid] = { answer: num(o.correct, 0, 0, options.length - 1), explanation: str(o.explanation, 1500) };
      totalXp += xp;
      return;
    }

    if (kind === "flag") {
      const prompt = str(o.prompt, 800);
      const answer = str(o.answer, 200);
      if (!prompt || !answer) return;
      const xp = num(o.xp, 25, 0, 200);
      const safe: Record<string, unknown> = { type: "flag", id: tid, prompt, xp };
      const hint = str(o.hint, 400);
      if (hint) safe.hint = hint;
      safeTasks.push(safe);
      keyTasks[tid] = { answer };
      totalXp += xp;
      return;
    }
    // Unknown kind — skip.
  });

  if (safeTasks.length === 0) {
    return { ok: false, error: "Add at least one task (reading, question, or flag)." };
  }

  const safeContent = {
    kind: "authored",
    id,
    title,
    description,
    difficulty,
    category: str(input.category, 60) || "Custom",
    icon: str(input.icon, 8) || "🎓",
    estimatedMinutes: num(input.estimatedMinutes, 15, 1, 240),
    xp: totalXp,
    prerequisites: [] as string[],
    tasks: safeTasks,
  };
  const answerKey = { tasks: keyTasks };
  return { ok: true, id, safeContent, answerKey };
}

/** Recombine the two projections into a full, gradable Room (server memory). */
export function recombineRoom(safeContent: Record<string, unknown>, answerKey: Record<string, unknown>): Room {
  const id = String(safeContent.id ?? "");
  const safeTasks = (Array.isArray(safeContent.tasks) ? safeContent.tasks : []) as Record<string, unknown>[];
  const keyMap = (answerKey.tasks ?? {}) as Record<string, Record<string, unknown>>;

  const tasks: RoomTask[] = safeTasks.map(s => {
    const type = String(s.type);
    const tid = String(s.id);
    const k = keyMap[tid] ?? {};
    if (type === "reading") {
      const cp = s.checkpoint as Record<string, unknown> | undefined;
      const cpKey = k.checkpoint as Record<string, unknown> | undefined;
      return {
        type: "reading", id: tid,
        heading: String(s.heading ?? ""), content: String(s.content ?? ""),
        ...(s.codeExample ? { codeExample: String(s.codeExample) } : {}),
        ...(cp ? { checkpoint: {
          question: String(cp.question ?? ""),
          options: (cp.options as string[]) ?? [],
          answer: Number(cpKey?.answer ?? 0),
          explanation: String(cpKey?.explanation ?? ""),
        } } : {}),
        xp: Number(s.xp ?? 5),
      };
    }
    if (type === "flag") {
      return {
        type: "flag", id: tid,
        prompt: String(s.prompt ?? ""),
        answer: String(k.answer ?? ""),
        ...(s.hint ? { hint: String(s.hint) } : {}),
        xp: Number(s.xp ?? 25),
      };
    }
    // question (default)
    return {
      type: "question", id: tid,
      question: String(s.question ?? ""),
      options: (s.options as string[]) ?? [],
      answer: Number(k.answer ?? 0),
      explanation: String(k.explanation ?? ""),
      xp: Number(s.xp ?? 25),
    };
  });

  return {
    id,
    title: String(safeContent.title ?? ""),
    description: String(safeContent.description ?? ""),
    difficulty: (["beginner", "intermediate", "advanced"].includes(String(safeContent.difficulty)) ? String(safeContent.difficulty) : "beginner") as Room["difficulty"],
    category: String(safeContent.category ?? "Custom"),
    estimatedMinutes: Number(safeContent.estimatedMinutes ?? 15),
    xp: Number(safeContent.xp ?? 0),
    icon: String(safeContent.icon ?? "🎓"),
    prerequisites: Array.isArray(safeContent.prerequisites) ? safeContent.prerequisites as string[] : [],
    tasks,
  };
}
