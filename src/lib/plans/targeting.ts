/**
 * Who a learning plan is for — PURE functions (unit-tested in targeting.test.ts).
 *
 * `isRecipient` mirrors the "assignments member read" RLS policy in migration
 * 0075 exactly, because the API reads with the service role (which bypasses RLS)
 * and must re-apply the same rule itself. `resolveRecipients` is the staff-side
 * expansion used for the progress matrix.
 */
import { DEFAULT_PRIORITY, type Audience, type PlanItem, type Priority } from "./types";

export interface PlanTargeting {
  audience: Audience;
  personal_user_id: string | null;
  archived_at?: string | null;
}
export interface TargetRow { group_id: string | null; user_id: string | null }

/**
 * Can `userId` (who belongs to the groups in `myGroupIds`) see this plan?
 * Same rule as the RLS policy: never archived; org-wide (and not personal), or
 * their personal plan, or a targeted plan naming them or one of their groups.
 */
export function isRecipient(
  userId: string,
  plan: PlanTargeting,
  targets: readonly TargetRow[],
  myGroupIds: ReadonlySet<string>,
): boolean {
  if (plan.archived_at) return false;
  if (plan.personal_user_id) return plan.personal_user_id === userId;
  if (plan.audience === "org") return true;
  return targets.some(t => (t.user_id !== null && t.user_id === userId) || (t.group_id !== null && myGroupIds.has(t.group_id)));
}

/**
 * Expand a plan to the concrete learners it applies to, for progress tracking.
 *  - personal plan → its owner (if eligible)
 *  - org-wide      → `orgWideIds` (the org's active students)
 *  - targeted      → direct users ∪ members of targeted groups
 * Everything is intersected with `eligible` (active, non-platform-admin members)
 * so someone deactivated or removed drops out of the matrix. Result is sorted by
 * `orderOf` when given (roster order), otherwise by id, for a stable table.
 */
export function resolveRecipients(
  plan: PlanTargeting,
  targets: readonly TargetRow[],
  groupMembers: ReadonlyMap<string, readonly string[]>,
  eligible: ReadonlySet<string>,
  orgWideIds: readonly string[],
  orderOf?: (id: string) => number,
): string[] {
  const out = new Set<string>();
  if (plan.personal_user_id) {
    if (eligible.has(plan.personal_user_id)) out.add(plan.personal_user_id);
  } else if (plan.audience === "org") {
    for (const id of orgWideIds) if (eligible.has(id)) out.add(id);
  } else {
    for (const t of targets) {
      if (t.user_id && eligible.has(t.user_id)) out.add(t.user_id);
      if (t.group_id) for (const id of groupMembers.get(t.group_id) ?? []) if (eligible.has(id)) out.add(id);
    }
  }
  const ids = [...out];
  return orderOf ? ids.sort((a, b) => orderOf(a) - orderOf(b) || a.localeCompare(b)) : ids.sort();
}

/**
 * Why a learner sees a plan, for the "via" label: "You" for personal/direct,
 * group names for group targets, "Everyone" for org-wide.
 */
export function viaLabels(
  userId: string,
  plan: PlanTargeting,
  targets: readonly TargetRow[],
  myGroupIds: ReadonlySet<string>,
  groupName: (id: string) => string | undefined,
): string[] {
  if (plan.personal_user_id) return ["You"];
  if (plan.audience === "org") return ["Everyone"];
  const labels: string[] = [];
  if (targets.some(t => t.user_id === userId)) labels.push("You");
  for (const t of targets) {
    if (t.group_id && myGroupIds.has(t.group_id)) {
      const n = groupName(t.group_id);
      if (n && !labels.includes(n)) labels.push(n);
    }
  }
  return labels;
}

/** Learner ordering: personal plan first, then plan priority, then soonest due, then newest. */
export function sortPlansForLearner<T extends { personal: boolean; priority: Priority; due_at: string | null; created_at: string }>(plans: readonly T[]): T[] {
  const due = (p: T) => (p.due_at ? Date.parse(p.due_at) : Number.POSITIVE_INFINITY);
  return [...plans].sort((a, b) =>
    (a.personal === b.personal ? 0 : a.personal ? -1 : 1)
    || a.priority - b.priority
    || due(a) - due(b)
    || Date.parse(b.created_at) - Date.parse(a.created_at),
  );
}

/** Items ordered by their own priority, keeping the manager's order within a priority (stable). */
export function sortItemsByPriority<T extends PlanItem>(items: readonly T[]): T[] {
  return items
    .map((it, i) => ({ it, i }))
    .sort((a, b) => (a.it.priority ?? DEFAULT_PRIORITY) - (b.it.priority ?? DEFAULT_PRIORITY) || a.i - b.i)
    .map(x => x.it);
}
