/**
 * Learning plans v2 (migration 0075) — shared, CLIENT-SAFE types and tiny
 * helpers. Nothing here imports the content corpus: the catalogue tree and the
 * resolved titles are built server-side (src/lib/plans/catalog.ts) and sent to
 * the browser as plain data, so no answer-bearing module reaches a client bundle.
 */

export type PlanItemKind = "room" | "scenario" | "lesson" | "quiz";
export const PLAN_ITEM_KINDS: readonly PlanItemKind[] = ["room", "scenario", "lesson", "quiz"];

/** 1 = high, 2 = normal (the default), 3 = low. */
export type Priority = 1 | 2 | 3;
export const DEFAULT_PRIORITY: Priority = 2;
export const PRIORITY_LABEL: Record<Priority, string> = { 1: "High", 2: "Normal", 3: "Low" };

/** One stored entry of `assignments.items`. v1 rows are `{kind, id}` only. */
export interface PlanItem {
  kind: PlanItemKind;
  id: string;
  priority?: Priority;
  note?: string;
}

/** Caps enforced by the API (the DB also bounds the array at 100). */
export const PLAN_LIMITS = {
  items: 100,
  note: 300,
  title: 160,
  instructions: 2000,
  groupName: 80,
  groupDescription: 300,
  targetGroups: 100,
  targetUsers: 1000,
  groupMembers: 1000,
  groupsPerOrg: 200,
} as const;

/** Stable identity of an item across tree, list and progress: "kind:id". */
export const itemKey = (i: { kind: string; id: string }) => `${i.kind}:${i.id}`;

/**
 * A node of the module tree. Leaves carry `item`; branches carry `children`.
 * `key` is unique across the whole tree (leaves use itemKey()).
 */
export interface CatalogNode {
  key: string;
  label: string;
  /** Small secondary text (difficulty, minutes, item kind…). */
  hint?: string;
  item?: { kind: PlanItemKind; id: string };
  children?: CatalogNode[];
}

/**
 * Per-user state of one item:
 *  done        — completed (room/lesson completed_at, quiz passed, any scenario run)
 *  in_progress — started but not finished
 *  not_started — nothing recorded
 *  untracked   — the platform records no completion for this item kind
 *                (org-authored library lessons), so it is shown but never counted
 */
export type ItemStatus = "done" | "in_progress" | "not_started" | "untracked";

/** One-character wire encoding of ItemStatus, used by the staff matrix. */
export const STATUS_CODE: Record<ItemStatus, string> = { done: "d", in_progress: "p", not_started: "n", untracked: "u" };
export const CODE_STATUS: Record<string, ItemStatus> = { d: "done", p: "in_progress", n: "not_started", u: "untracked" };

/** An item resolved for display: title + deep link (+ the caller's status). */
export interface ResolvedPlanItem extends PlanItem {
  title: string;
  href: string;
  /** Org-authored content (the "Custom" branch of the tree). */
  custom?: boolean;
  status?: ItemStatus;
}

export type Audience = "org" | "targeted";

/** What a learner receives (GET /api/org/assignments?view=mine). */
export interface LearnerPlan {
  id: string;
  title: string;
  instructions: string | null;
  due_at: string | null;
  priority: Priority;
  personal: boolean;
  /** Why the learner sees it: "Everyone", group names, or "You". */
  via: string[];
  items: ResolvedPlanItem[];
  created_at: string;
}

/** What staff receive per plan (GET /api/org/assignments). */
export interface StaffPlan {
  id: string;
  title: string;
  instructions: string | null;
  due_at: string | null;
  priority: Priority;
  audience: Audience;
  targets: { group_ids: string[]; user_ids: string[] };
  archived_at: string | null;
  created_at: string;
  updated_at: string;
  items: ResolvedPlanItem[];
  /** users × items matrix: one row per recipient, `statuses` is STATUS_CODE chars in item order. */
  progress: { user_id: string; name: string; statuses: string }[];
  /** Recipients who have finished every tracked item. */
  completed: number;
}

export interface GroupRow {
  id: string;
  name: string;
  description: string | null;
  member_ids: string[];
  created_at: string;
}
