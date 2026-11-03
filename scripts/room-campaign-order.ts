// Prints rooms in the order the platform unlocks them: prerequisite depth,
// then difficulty, then file order (the same ranking recommendNextRoom uses).
// Usage: npx tsx scripts/room-campaign-order.ts
import { ROOMS_META } from "../src/data/roomsMeta";
import { getRoomExperience } from "../src/lib/rooms/experience";

const DIFF: Record<string, number> = { beginner: 0, intermediate: 1, advanced: 2 };
const memo = new Map<string, number>();
function depth(id: string): number {
  const r = ROOMS_META.find(x => x.id === id);
  if (!r || r.prerequisites.length === 0) return 0;
  if (memo.has(id)) return memo.get(id)!;
  memo.set(id, 0);
  const d = 1 + Math.max(...r.prerequisites.map(depth));
  memo.set(id, d);
  return d;
}
const order = ROOMS_META.map((r, i) => ({ r, i, d: depth(r.id) }))
  .sort((a, b) => a.d - b.d || DIFF[a.r.difficulty] - DIFF[b.r.difficulty] || a.i - b.i);
order.forEach(({ r, d }, n) => {
  const op = getRoomExperience(r.id, r.tasks.map(t => t.id)) ? " [OPERATION]" : "";
  const types = [...new Set(r.tasks.map(t => t.type))].join(",");
  console.log(`${String(n + 1).padStart(3)}  d${d} ${r.difficulty.padEnd(12)} ${r.id.padEnd(44)} ${r.tasks.length}t ${r.category} | prereq: ${r.prerequisites.join(",") || "-"} | ${types}${op}`);
});
