import "server-only";
/**
 * Server-side data access shared by the learning-plan routes
 * (/api/org/assignments, /api/org/groups, /api/org/students/[id]/plan).
 *
 * Every read here uses the SERVICE-ROLE client, which bypasses RLS — so every
 * query is pinned with .eq("org_id", orgId) explicitly, and learner visibility
 * is re-applied with isRecipient() (the same rule as the 0075 RLS policy).
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { getPlanCatalog, needsOrgCatalog, type PlanCatalog } from "./catalog";
import { buildProgressIndex, itemStatus, type ProgressIndex, type ProgressRows } from "./completion";
import { parsePriority, sanitizePlanItems } from "./sanitize";
import { isRecipient, sortItemsByPriority, sortPlansForLearner, viaLabels, type TargetRow } from "./targeting";
import type { Audience, LearnerPlan, PlanItem, Priority, ResolvedPlanItem } from "./types";

export interface AssignmentDbRow {
  id: string;
  title: string;
  instructions: string | null;
  items: unknown;
  due_at: string | null;
  created_at: string;
  updated_at: string;
  audience: Audience | null;
  priority: number | null;
  personal_user_id: string | null;
  archived_at: string | null;
}
export const ASSIGNMENT_COLUMNS =
  "id, title, instructions, items, due_at, created_at, updated_at, audience, priority, personal_user_id, archived_at";

export interface OrgMemberLite {
  user_id: string;
  role: string;
  status: string;
  name: string;
}

/** Page through a PostgREST query (default page cap is 1000 rows). */
export async function fetchAll<T>(
  page: (from: number, to: number) => PromiseLike<{ data: T[] | null; error: { message: string } | null }>,
  max = 20_000,
): Promise<T[]> {
  const size = 1000;
  const out: T[] = [];
  for (let from = 0; from < max; from += size) {
    const { data, error } = await page(from, from + size - 1);
    if (error) throw new Error(error.message);
    const rows = data ?? [];
    out.push(...rows);
    if (rows.length < size) break;
  }
  return out;
}

/**
 * The org's members, minus platform super-admins (who traverse orgs invisibly —
 * same exclusion as the roster). Includes every status; callers filter.
 */
export async function loadOrgMembers(admin: SupabaseClient, orgId: string): Promise<OrgMemberLite[]> {
  const rows = await fetchAll<{ user_id: string; role: string; status: string; profiles: unknown }>((from, to) =>
    admin.from("org_members")
      .select("user_id, role, status, profiles(handle, display_name, is_platform_admin)")
      .eq("org_id", orgId)
      .order("joined_at", { ascending: true })
      .range(from, to));
  return rows
    .filter(m => !(m.profiles as { is_platform_admin?: boolean } | null)?.is_platform_admin)
    .map(m => {
      const p = m.profiles as { handle?: string | null; display_name?: string | null } | null;
      return { user_id: m.user_id, role: m.role, status: m.status, name: p?.display_name || p?.handle || m.user_id.slice(0, 8) };
    });
}

/**
 * Progress rows for the org, optionally narrowed to ONE learner. Org-pinned on
 * every table (progress rows are stamped with the org they were earned in).
 */
export async function loadProgress(admin: SupabaseClient, orgId: string, userId?: string): Promise<ProgressIndex> {
  const read = <T,>(table: string, columns: string) => fetchAll<T>((from, to) => {
    let q = admin.from(table).select(columns).eq("org_id", orgId);
    if (userId) q = q.eq("user_id", userId);
    return q.range(from, to) as unknown as PromiseLike<{ data: T[] | null; error: { message: string } | null }>;
  });
  const [rooms, scenarios, quizzes, lessons] = await Promise.all([
    read<ProgressRows["rooms"][number]>("room_progress", "user_id, room_id, completed_at"),
    read<ProgressRows["scenarios"][number]>("scenario_history", "user_id, slug"),
    read<ProgressRows["quizzes"][number]>("quiz_progress", "user_id, quiz_slug, passed"),
    read<ProgressRows["lessons"][number]>("lesson_progress", "user_id, lesson_key, completed_at"),
  ]);
  return buildProgressIndex({ rooms, scenarios, quizzes, lessons });
}

/** Stored items → display items (title, deep link, optional status for `userId`). */
export function resolveItems(
  raw: unknown,
  catalog: PlanCatalog,
  progress?: { idx: ProgressIndex; userId: string },
): ResolvedPlanItem[] {
  return sanitizePlanItems(raw, catalog.isKnown).map((it: PlanItem) => {
    const e = catalog.index.get(`${it.kind}:${it.id}`)!;
    const r: ResolvedPlanItem = { ...it, title: e.title, href: e.href };
    if (e.custom) r.custom = true;
    if (progress) r.status = itemStatus(progress.idx, progress.userId, it);
    return r;
  });
}

/**
 * Everything `userId` is assigned in `orgId` — org-wide, targeted at them or a
 * group of theirs, and their personal plan — with their own status per item,
 * ordered for the learner (personal first, then priority, then due date).
 */
export async function loadLearnerPlans(admin: SupabaseClient, orgId: string, userId: string): Promise<LearnerPlan[]> {
  const [plansRes, myGroupsRes] = await Promise.all([
    admin.from("assignments").select(ASSIGNMENT_COLUMNS).eq("org_id", orgId).is("archived_at", null).limit(500),
    admin.from("org_group_members").select("group_id").eq("org_id", orgId).eq("user_id", userId),
  ]);
  if (plansRes.error) throw new Error(plansRes.error.message);
  const rows = (plansRes.data ?? []) as AssignmentDbRow[];
  const myGroupIds = new Set((myGroupsRes.data ?? []).map(g => g.group_id as string));

  const targetedIds = rows.filter(r => r.audience === "targeted" && !r.personal_user_id).map(r => r.id);
  const targetsByPlan = new Map<string, TargetRow[]>();
  if (targetedIds.length) {
    const { data: t } = await admin.from("assignment_targets")
      .select("assignment_id, group_id, user_id").eq("org_id", orgId).in("assignment_id", targetedIds);
    for (const row of (t ?? []) as (TargetRow & { assignment_id: string })[]) {
      const arr = targetsByPlan.get(row.assignment_id) ?? [];
      arr.push({ group_id: row.group_id, user_id: row.user_id });
      targetsByPlan.set(row.assignment_id, arr);
    }
  }

  const visible = rows.filter(r => isRecipient(
    userId,
    { audience: r.audience === "targeted" ? "targeted" : "org", personal_user_id: r.personal_user_id, archived_at: r.archived_at },
    targetsByPlan.get(r.id) ?? [],
    myGroupIds,
  ));
  if (visible.length === 0) return [];

  // Only the names of groups that actually target this learner are ever read.
  const groupNames = new Map<string, string>();
  const neededGroups = [...new Set(visible.flatMap(r => (targetsByPlan.get(r.id) ?? []).map(t => t.group_id).filter((g): g is string => !!g && myGroupIds.has(g))))];
  if (neededGroups.length) {
    const { data: g } = await admin.from("org_groups").select("id, name").eq("org_id", orgId).in("id", neededGroups);
    for (const row of g ?? []) groupNames.set(row.id as string, row.name as string);
  }

  const [catalog, idx] = await Promise.all([
    getPlanCatalog(admin, orgId, needsOrgCatalog(visible.map(r => r.items))),
    loadProgress(admin, orgId, userId),
  ]);

  const plans: LearnerPlan[] = visible.map(r => {
    const targeting = { audience: (r.audience === "targeted" ? "targeted" : "org") as Audience, personal_user_id: r.personal_user_id };
    return {
      id: r.id,
      title: r.title,
      instructions: r.instructions,
      due_at: r.due_at,
      priority: parsePriority(r.priority) as Priority,
      personal: r.personal_user_id === userId,
      via: viaLabels(userId, targeting, targetsByPlan.get(r.id) ?? [], myGroupIds, id => groupNames.get(id)),
      items: sortItemsByPriority(resolveItems(r.items, catalog, { idx, userId })),
      created_at: r.created_at,
    };
  }).filter(p => p.items.length > 0);

  return sortPlansForLearner(plans);
}
