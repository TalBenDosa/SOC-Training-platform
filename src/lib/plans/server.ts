import "server-only";
/**
 * Server-side data access shared by the learning-plan routes
 * (/api/org/assignments, /api/org/groups, /api/org/students/[id]/plan).
 *
 * Every read here uses the SERVICE-ROLE client, which bypasses RLS — so every
 * query is pinned with .eq("org_id", orgId) explicitly, and learner visibility
 * is re-applied with isRecipient() (the same rule as the 0075 RLS policy).
 *
 * Every paged read has a stable ORDER BY (PostgREST pages are only consistent
 * over a total order) and fails LOUDLY — PlanDataError("cap") — rather than
 * silently truncating when a row cap is reached. A missing 0075 column/table
 * surfaces as PlanDataError("schema") so the routes can degrade cleanly when the
 * code is deployed ahead of the migration (the runbook order is migration first).
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { getPlanCatalog, needsOrgCatalog, type PlanCatalog } from "./catalog";
import { buildProgressIndex, itemStatus, type ProgressIndex, type ProgressRows } from "./completion";
import { isUuid, parsePriority, sanitizePlanItems } from "./sanitize";
import { isRecipient, sortItemsByPriority, sortPlansForLearner, viaLabels, type TargetRow } from "./targeting";
import type { Audience, LearnerPlan, PlanItem, PlanItemKind, Priority, ResolvedPlanItem } from "./types";

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

// ── Errors ───────────────────────────────────────────────────────────────────
type DbError = { message: string; code?: string };

/** "cap": a row cap was hit · "schema": 0075 isn't applied · "db": anything else. */
export class PlanDataError extends Error {
  constructor(message: string, public readonly kind: "cap" | "schema" | "db") {
    super(message);
    this.name = "PlanDataError";
  }
}

// Postgres undefined_column / undefined_table, PostgREST unknown column /
// relationship / table-not-in-schema-cache.
const SCHEMA_CODES = new Set(["42703", "42P01", "PGRST200", "PGRST204", "PGRST205"]);

export function toPlanDataError(e: DbError, context: string): PlanDataError {
  const kind = e.code && SCHEMA_CODES.has(e.code) ? "schema" : "db";
  return new PlanDataError(`${context}: ${e.message}${e.code ? ` (${e.code})` : ""}`, kind);
}

/** Throw on a PostgREST error, classifying it. */
export function check<T extends { error: DbError | null }>(res: T, context: string): T {
  if (res.error) throw toPlanDataError(res.error, context);
  return res;
}

/**
 * Page through a PostgREST query (its per-request cap is 1000 rows). The
 * caller's query MUST carry a stable .order(). Throws PlanDataError("cap") if
 * `max` rows are reached with more still coming — never a silent truncation.
 */
export async function fetchAll<T>(
  page: (from: number, to: number) => PromiseLike<{ data: T[] | null; error: DbError | null }>,
  context: string,
  max = 50_000,
): Promise<T[]> {
  const size = 1000;
  const out: T[] = [];
  for (let from = 0; ; from += size) {
    const { data, error } = await page(from, from + size - 1);
    if (error) throw toPlanDataError(error, context);
    const rows = data ?? [];
    out.push(...rows);
    if (rows.length < size) return out;
    if (out.length >= max) {
      console.error(`[plans] row cap of ${max} reached for ${context}`);
      throw new PlanDataError(`${context}: more than ${max} rows`, "cap");
    }
  }
}

/** Split `list` into chunks of `n` (keeps request URLs short for .in() filters). */
export function chunk<T>(list: readonly T[], n: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < list.length; i += n) out.push(list.slice(i, i + n));
  return out;
}

// ── Members ──────────────────────────────────────────────────────────────────
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
      .order("user_id", { ascending: true })
      .range(from, to), "org_members");
  return rows
    .filter(m => !(m.profiles as { is_platform_admin?: boolean } | null)?.is_platform_admin)
    .map(m => {
      const p = m.profiles as { handle?: string | null; display_name?: string | null } | null;
      return { user_id: m.user_id, role: m.role, status: m.status, name: p?.display_name || p?.handle || m.user_id.slice(0, 8) };
    });
}

/** Ids a plan may target / a group may contain / a personal plan may belong to: ACTIVE members only. */
export function activeMemberIds(members: readonly OrgMemberLite[]): Set<string> {
  return new Set(members.filter(m => m.status === "active").map(m => m.user_id));
}

// ── Progress ─────────────────────────────────────────────────────────────────
const PROGRESS_SOURCES: Record<PlanItemKind, { table: string; columns: string; key: string; order: string[] }> = {
  room:     { table: "room_progress",    columns: "user_id, room_id, completed_at",   key: "room_id",    order: ["user_id", "room_id"] },
  scenario: { table: "scenario_history", columns: "user_id, slug",                    key: "slug",       order: ["id"] },
  quiz:     { table: "quiz_progress",    columns: "user_id, quiz_slug, passed",       key: "quiz_slug",  order: ["user_id", "quiz_slug"] },
  lesson:   { table: "lesson_progress",  columns: "user_id, lesson_key, completed_at", key: "lesson_key", order: ["user_id", "lesson_key"] },
};

export interface ProgressScope {
  /**
   * Pin rows to this org (staff views — a manager only sees progress earned
   * inside their org). null = the user's OWN progress wherever it was earned
   * (the learner's view of their own plan, as in v1).
   */
  orgId: string | null;
  /** Restrict to these learners (required when orgId is null). */
  userIds?: readonly string[];
  /** Restrict to the ids these items reference; an empty list reads nothing. */
  items?: readonly Pick<PlanItem, "kind" | "id">[];
}

export async function loadProgress(admin: SupabaseClient, scope: ProgressScope): Promise<ProgressIndex> {
  if (!scope.orgId && !(scope.userIds && scope.userIds.length)) {
    throw new PlanDataError("loadProgress: an unpinned read needs explicit user ids", "db");
  }
  if (scope.userIds && scope.userIds.length === 0) return new Map();

  const users = scope.userIds ? [...new Set(scope.userIds)] : null;
  const userSet = users ? new Set(users) : null;
  // Small user sets go into the SQL filter; large ones are filtered in memory
  // (a few hundred uuids in a query string would overflow the request URL).
  const sqlUsers = users && users.length <= 100 ? users : null;

  const idsByKind = new Map<PlanItemKind, string[]>();
  if (scope.items) {
    for (const it of scope.items) {
      const arr = idsByKind.get(it.kind) ?? [];
      if (!arr.includes(it.id)) arr.push(it.id);
      idsByKind.set(it.kind, arr);
    }
  }

  const read = async <T extends { user_id: string }>(kind: PlanItemKind): Promise<T[]> => {
    const src = PROGRESS_SOURCES[kind];
    // With an item filter, only the kinds (and ids) the plans use are read.
    const idChunks: (string[] | null)[] = scope.items ? chunk(idsByKind.get(kind) ?? [], 60) : [null];
    const out: T[] = [];
    for (const ids of idChunks) {
      const rows = await fetchAll<T>((from, to) => {
        let q = admin.from(src.table).select(src.columns);
        if (scope.orgId) q = q.eq("org_id", scope.orgId);
        if (sqlUsers) q = sqlUsers.length === 1 ? q.eq("user_id", sqlUsers[0]) : q.in("user_id", sqlUsers);
        if (ids) q = q.in(src.key, ids);
        for (const col of src.order) q = q.order(col, { ascending: true });
        return q.range(from, to) as unknown as PromiseLike<{ data: T[] | null; error: DbError | null }>;
      }, src.table);
      out.push(...(userSet ? rows.filter(r => userSet.has(r.user_id)) : rows));
    }
    return out;
  };

  const [rooms, scenarios, quizzes, lessons] = await Promise.all([
    read<ProgressRows["rooms"][number]>("room"),
    read<ProgressRows["scenarios"][number]>("scenario"),
    read<ProgressRows["quizzes"][number]>("quiz"),
    read<ProgressRows["lessons"][number]>("lesson"),
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

// ── A learner's plans ────────────────────────────────────────────────────────
/**
 * Everything `userId` is assigned in `orgId` — org-wide, targeted at them or a
 * group of theirs, and their personal plan — with their status per item,
 * ordered for the learner (personal first, then priority, then due date).
 *
 * Narrowed in SQL: other learners' personal plans are never read, and only the
 * target rows naming this user or one of their groups are fetched.
 *
 * `progress`: "self" (the learner looking at their own plan) counts progress
 * earned anywhere, as v1 did; "org" (a manager on the student page) counts only
 * progress earned inside this org.
 */
export async function loadLearnerPlans(
  admin: SupabaseClient,
  orgId: string,
  userId: string,
  progress: "self" | "org",
): Promise<LearnerPlan[]> {
  if (!isUuid(userId)) throw new PlanDataError("loadLearnerPlans: invalid user id", "db");

  const [rows, myGroups] = await Promise.all([
    fetchAll<AssignmentDbRow>((from, to) =>
      admin.from("assignments").select(ASSIGNMENT_COLUMNS)
        .eq("org_id", orgId)
        .is("archived_at", null)
        .or(`personal_user_id.is.null,personal_user_id.eq.${userId}`)
        .order("created_at", { ascending: false })
        .order("id", { ascending: true })
        .range(from, to), "assignments"),
    fetchAll<{ group_id: string }>((from, to) =>
      admin.from("org_group_members").select("group_id")
        .eq("org_id", orgId).eq("user_id", userId)
        .order("group_id", { ascending: true })
        .range(from, to), "org_group_members"),
  ]);
  const myGroupIds = new Set(myGroups.map(g => g.group_id));

  // Only the target rows that could make this user a recipient.
  const targetsByPlan = new Map<string, TargetRow[]>();
  if (rows.some(r => r.audience === "targeted" && !r.personal_user_id)) {
    const groupList = [...myGroupIds].filter(isUuid);
    const who = groupList.length ? `user_id.eq.${userId},group_id.in.(${groupList.join(",")})` : `user_id.eq.${userId}`;
    const targets = await fetchAll<TargetRow & { assignment_id: string }>((from, to) =>
      admin.from("assignment_targets").select("assignment_id, group_id, user_id")
        .eq("org_id", orgId)
        .or(who)
        .order("id", { ascending: true })
        .range(from, to), "assignment_targets");
    for (const t of targets) {
      const arr = targetsByPlan.get(t.assignment_id) ?? [];
      arr.push({ group_id: t.group_id, user_id: t.user_id });
      targetsByPlan.set(t.assignment_id, arr);
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
  for (const ids of chunk(neededGroups, 100)) {
    const g = check(await admin.from("org_groups").select("id, name").eq("org_id", orgId).in("id", ids), "org_groups");
    for (const row of g.data ?? []) groupNames.set(row.id as string, row.name as string);
  }

  const catalog = await getPlanCatalog(admin, orgId, needsOrgCatalog(visible.map(r => r.items)));
  const resolvedItems = visible.map(r => sanitizePlanItems(r.items, catalog.isKnown));
  const idx = await loadProgress(admin, {
    orgId: progress === "org" ? orgId : null,
    userIds: [userId],
    items: resolvedItems.flat(),
  });

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
