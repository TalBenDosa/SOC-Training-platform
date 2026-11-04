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

/** How many prerequisite steps sit under a room (0 = no prerequisites). Memoised per call site. */
function makePrereqDepth(rooms: { id: string; prerequisites: string[] }[]): (roomId: string) => number {
  const byId = new Map(rooms.map(r => [r.id, r]));
  const memo = new Map<string, number>();
  const depth = (roomId: string): number => {
    const room = byId.get(roomId);
    if (!room || room.prerequisites.length === 0) return 0;
    if (memo.has(roomId)) return memo.get(roomId)!;
    memo.set(roomId, 0); // cycle guard
    const d = 1 + Math.max(...room.prerequisites.map(depth));
    memo.set(roomId, d);
    return d;
  };
  return depth;
}

/**
 * The learning order of the rooms list: level (beginner, intermediate, advanced), then
 * prerequisite depth (foundational first), then file order. A room's level is never below
 * a prerequisite's (rooms.test.ts), so every room comes after the rooms it builds on.
 */
export function orderRoomsForLearning<T extends { id: string; difficulty: string; prerequisites: string[] }>(rooms: T[]): T[] {
  const depth = makePrereqDepth([...ROOMS_META, ...rooms]);
  const idx = new Map(rooms.map((r, i) => [r.id, i]));
  return rooms.slice().sort((a, b) =>
    ((DIFF_RANK[a.difficulty] ?? 1) - (DIFF_RANK[b.difficulty] ?? 1)) ||
    (depth(a.id) - depth(b.id)) ||
    (idx.get(a.id)! - idx.get(b.id)!),
  );
}

/**
 * The single room to point the learner at: unlocked, not-yet-passed, ranked by
 * PREREQUISITE DEPTH (shallow/foundational first) then difficulty then file
 * order. Prefers a room already started ("Continue") over a new one. `excludeId`
 * skips the room just completed so it never recommends itself. It always follows
 * prerequisite order, even when the org leaves every room open, so the suggestion
 * stays gradual.
 */
export function recommendNextRoom(
  progress: RoomProgressLike,
  excludeId?: string,
): { room: RoomMeta; started: boolean } | null {
  const prereqDepth = makePrereqDepth(ROOMS_META);

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
