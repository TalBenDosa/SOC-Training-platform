import "server-only";
/**
 * The questions a class gets wrong most on the first try, with the wrong answer most of
 * them chose. Many students picking the SAME wrong answer usually means the question or the
 * lesson behind it is the problem, not the students. Server-side: texts and right answers
 * come from full rooms (getEffectiveRoom), returned only to the class's own staff.
 */
import { getEffectiveRoom } from "@/lib/rooms/resolve";
import { TASK_TYPE_LABEL } from "@/lib/feedback/labels";
import { describe, type StoredAttempt } from "./mistakeView";
import type { ItemResult } from "./firstTry";

export interface CommonMistake {
  key: string;
  room_id: string;
  room_title: string;
  task_id: string;
  task_position: string | null;
  type_label: string;
  prompt: string | null;
  correct: string | null;
  explanation: string | null;
  attempted: number;          // students who answered it
  wrong_first: number;        // of them, wrong on the first try
  rate: number;               // whole percent
  common_wrong: { text: string | null; count: number } | null;
}

export async function commonMistakes(itemsByUser: Map<string, ItemResult<StoredAttempt>[]>, orgId: string, limit = 15): Promise<CommonMistake[]> {
  const by = new Map<string, { items: ItemResult<StoredAttempt>[] }>();
  for (const items of itemsByUser.values()) for (const it of items) {
    const e = by.get(it.key) ?? { items: [] };
    e.items.push(it); by.set(it.key, e);
  }
  const minStudents = Math.min(3, Math.max(1, itemsByUser.size));
  const ranked = [...by.entries()]
    .map(([key, e]) => ({ key, items: e.items, wrong: e.items.filter(i => !i.firstTryCorrect) }))
    .filter(x => x.items.length >= minStudents && x.wrong.length > 0)
    .sort((a, b) => b.wrong.length / b.items.length - a.wrong.length / a.items.length || b.wrong.length - a.wrong.length)
    .slice(0, limit);

  const roomIds = [...new Set(ranked.map(r => r.items[0].room_id))];
  const rooms = new Map(await Promise.all(roomIds.map(async id => [id, await getEffectiveRoom(id, orgId).catch(() => null)] as const)));

  return ranked.map(({ key, items, wrong }) => {
    const first = items[0];
    const room = rooms.get(first.room_id) ?? null;
    const idx = room ? room.tasks.findIndex(t => t.id === first.task_id) : -1;
    const task = idx >= 0 ? room!.tasks[idx] : undefined;
    // The most common first wrong answer, by what was submitted.
    const counts = new Map<string, { n: number; item: ItemResult<StoredAttempt> }>();
    for (const w of wrong) {
      const sig = JSON.stringify(w.attempts[0]?.submitted ?? null);
      const c = counts.get(sig) ?? { n: 0, item: w };
      c.n++; counts.set(sig, c);
    }
    const top = [...counts.values()].sort((a, b) => b.n - a.n)[0];
    const d = describe(task, top.item);
    const qCount = task?.type === "log_analysis" ? task.questions.length : 0;
    return {
      key, room_id: first.room_id, room_title: room?.title ?? first.room_id, task_id: first.task_id,
      task_position: room && idx >= 0 ? `Task ${idx + 1} of ${room.tasks.length}${qCount > 1 ? ` · question ${(first.question_index ?? 0) + 1} of ${qCount}` : ""}` : null,
      type_label: TASK_TYPE_LABEL[first.task_type ?? ""] ?? first.task_type ?? "Task",
      prompt: d.prompt, correct: d.correct, explanation: d.explanation,
      attempted: items.length, wrong_first: wrong.length, rate: Math.round((wrong.length / items.length) * 100),
      common_wrong: top ? { text: d.chosen, count: top.n } : null,
    };
  });
}
