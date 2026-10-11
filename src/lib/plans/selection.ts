/**
 * Tree-tick → selected-items logic for the plan editors — PURE (unit-tested in
 * selection.test.ts). Ticking a branch adds every leaf under it in tree order;
 * the plan is capped at PLAN_LIMITS.items, and anything over the cap is
 * reported back as `dropped` so the editor can say so instead of silently
 * truncating.
 */
import { PLAN_LIMITS, itemKey, type CatalogNode, type PlanItem } from "./types";

export function applyToggle(
  items: readonly PlanItem[],
  keys: readonly string[],
  select: boolean,
  leaves: ReadonlyMap<string, CatalogNode>,
  max: number = PLAN_LIMITS.items,
): { items: PlanItem[]; dropped: number } {
  if (!select) {
    const drop = new Set(keys);
    return { items: items.filter(i => !drop.has(itemKey(i))), dropped: 0 };
  }
  const have = new Set(items.map(itemKey));
  const next = [...items];
  let dropped = 0;
  for (const k of keys) {
    const leaf = leaves.get(k);
    if (!leaf?.item || have.has(k)) continue;
    have.add(k);
    if (next.length >= max) { dropped++; continue; }
    next.push({ kind: leaf.item.kind, id: leaf.item.id });
  }
  return { items: next, dropped };
}

/** The editor notice for a truncated tick, or null. */
export function capNotice(dropped: number, max: number = PLAN_LIMITS.items): string | null {
  if (dropped <= 0) return null;
  return `A plan holds at most ${max} items — ${dropped} more ${dropped === 1 ? "was" : "were"} not added. Split the work into two plans or untick some items.`;
}
