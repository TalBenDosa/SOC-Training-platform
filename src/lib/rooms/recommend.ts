import { ROOMS_META, type RoomMeta } from "@/data/roomsMeta";

/**
 * Shared "which room next?" logic — used by BOTH the rooms list (the Start
 * here / Continue banner) and the Room-Complete screen, so the recommendation
 * a learner sees when they finish a room matches the one on the list. It used
 * to live only in rooms/page.tsx, which meant the completion screen offered no
 * next step at all (just "Back to Rooms") right at the moment of highest momentum.
 */

type RoomProg = { completedAt?: string; completedTaskIds?: string[] } | undefined;
export type RoomProgressLike = Record<string, RoomProg>;

/** A room is locked until every prerequisite room has been PASSED (completedAt set). */
export function isRoomLocked(roomId: string, progress: RoomProgressLike): boolean {
  const room = ROOMS_META.find(r => r.id === roomId);
  if (!room || room.prerequisites.length === 0) return false;
  return !room.prerequisites.every(p => !!progress[p]?.completedAt);
}

const DIFF_RANK: Record<string, number> = { beginner: 0, intermediate: 1, advanced: 2 };

/**
 * The single room to point the learner at: unlocked, not-yet-passed, ranked by
 * PREREQUISITE DEPTH (shallow/foundational first) then difficulty then file
 * order. Prefers a room already started ("Continue") over a new one. `excludeId`
 * skips the room just completed so it never recommends itself.
 */
export function recommendNextRoom(
  progress: RoomProgressLike,
  excludeId?: string,
): { room: RoomMeta; started: boolean } | null {
  const depthMemo = new Map<string, number>();
  function prereqDepth(roomId: string): number {
    const room = ROOMS_META.find(r => r.id === roomId);
    if (!room || room.prerequisites.length === 0) return 0;
    if (depthMemo.has(roomId)) return depthMemo.get(roomId)!;
    depthMemo.set(roomId, 0); // cycle guard
    const d = 1 + Math.max(...room.prerequisites.map(prereqDepth));
    depthMemo.set(roomId, d);
    return d;
  }

  const available = ROOMS_META.filter(
    r => r.id !== excludeId && !progress[r.id]?.completedAt && !isRoomLocked(r.id, progress),
  );
  const started = available.filter(r => (progress[r.id]?.completedTaskIds?.length ?? 0) > 0);
  const room = (started.length > 0 ? started : available)
    .slice()
    .sort((a, b) =>
      (prereqDepth(a.id) - prereqDepth(b.id)) ||
      ((DIFF_RANK[a.difficulty] ?? 1) - (DIFF_RANK[b.difficulty] ?? 1)) ||
      (ROOMS_META.indexOf(a) - ROOMS_META.indexOf(b)),
    )[0] ?? null;

  if (!room) return null;
  return { room, started: (progress[room.id]?.completedTaskIds?.length ?? 0) > 0 };
}
