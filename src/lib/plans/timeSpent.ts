import "server-only";
/**
 * Time a learner actually spent on plan items, to set beside the manager's target
 * (PlanItem.target_minutes; demo feedback 2026-11).
 *
 * What the platform records today, with no new table:
 *  - rooms: room_progress.telemetry, one entry per finished task with decisionLatencyMs (from the
 *    task being shown to it being completed, capped per task so an idle tab does not count);
 *  - scenarios: scenario_history.time_taken, seconds per completed run (summed over runs);
 *  - lessons and quizzes: content_time (migration 0109), active seconds sent by the page.
 * Where a kind is not measured (a custom org lesson; content_time not deployed yet) the item
 * comes back as `null` ("not measured"), never 0.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { chunk, fetchAll } from "./server";
import { itemKey, type PlanItem } from "./types";

/** user id -> item key -> seconds, plus the kinds that could not be measured in this read. */
export type TimeIndex = Map<string, Map<string, number>> & { unmeasured?: Set<PlanItem["kind"]> };

const MAX_TASK_MS = 30 * 60_000;

export function timeMeasured(item: Pick<PlanItem, "kind" | "id">, idx?: TimeIndex): boolean {
  if (idx?.unmeasured?.has(item.kind)) return false;
  // Custom org lessons have no page that reports time.
  return !(item.kind === "lesson" && item.id.startsWith("org-"));
}

export async function loadTimeSpent(
  admin: SupabaseClient,
  scope: { orgId: string | null; userIds: readonly string[]; items: readonly Pick<PlanItem, "kind" | "id">[] },
): Promise<TimeIndex> {
  const idx: TimeIndex = new Map();
  const users = [...new Set(scope.userIds)];
  if (users.length === 0) return idx;
  const add = (user: string, key: string, sec: number) => {
    if (!(sec > 0)) return;
    let m = idx.get(user);
    if (!m) { m = new Map(); idx.set(user, m); }
    m.set(key, (m.get(key) ?? 0) + sec);
  };
  const userSet = new Set(users);
  const sqlUsers = users.length <= 100 ? users : null;
  const roomIds = [...new Set(scope.items.filter(i => i.kind === "room").map(i => i.id))];
  const slugs = [...new Set(scope.items.filter(i => i.kind === "scenario").map(i => i.id))];
  const contentIds = { lesson: [...new Set(scope.items.filter(i => i.kind === "lesson" && !i.id.startsWith("org-")).map(i => i.id))], quiz: [...new Set(scope.items.filter(i => i.kind === "quiz").map(i => i.id))] };

  for (const ids of chunk(roomIds, 60)) {
    const rows = await fetchAll<{ user_id: string; room_id: string; telemetry: unknown }>((from, to) => {
      let q = admin.from("room_progress").select("user_id, room_id, telemetry").in("room_id", ids);
      if (scope.orgId) q = q.eq("org_id", scope.orgId);
      if (sqlUsers) q = q.in("user_id", sqlUsers);
      return q.order("user_id", { ascending: true }).order("room_id", { ascending: true }).range(from, to) as never;
    }, "room_progress");
    for (const r of rows) {
      if (!userSet.has(r.user_id) || !Array.isArray(r.telemetry)) continue;
      let ms = 0;
      for (const t of r.telemetry as { decisionLatencyMs?: unknown }[]) {
        const v = Number(t?.decisionLatencyMs);
        if (Number.isFinite(v) && v > 0) ms += Math.min(v, MAX_TASK_MS);
      }
      add(r.user_id, itemKey({ kind: "room", id: r.room_id }), Math.round(ms / 1000));
    }
  }

  for (const ids of chunk(slugs, 60)) {
    const rows = await fetchAll<{ user_id: string; slug: string; time_taken: number | null }>((from, to) => {
      let q = admin.from("scenario_history").select("user_id, slug, time_taken").in("slug", ids);
      if (scope.orgId) q = q.eq("org_id", scope.orgId);
      if (sqlUsers) q = q.in("user_id", sqlUsers);
      return q.order("id", { ascending: true }).range(from, to) as never;
    }, "scenario_history");
    for (const r of rows) {
      if (!userSet.has(r.user_id)) continue;
      add(r.user_id, itemKey({ kind: "scenario", id: r.slug }), Math.max(0, Math.round(Number(r.time_taken) || 0)));
    }
  }
  for (const kind of ["lesson", "quiz"] as const) {
    try {
      for (const ids of chunk(contentIds[kind], 60)) {
        const rows = await fetchAll<{ user_id: string; item_id: string; seconds: number }>((from, to) => {
          let q = admin.from("content_time").select("user_id, item_id, seconds").eq("kind", kind).in("item_id", ids);
          if (scope.orgId) q = q.eq("org_id", scope.orgId);
          if (sqlUsers) q = q.in("user_id", sqlUsers);
          return q.order("user_id", { ascending: true }).order("item_id", { ascending: true }).range(from, to) as never;
        }, "content_time");
        for (const r of rows) if (userSet.has(r.user_id)) add(r.user_id, itemKey({ kind, id: r.item_id }), Number(r.seconds) || 0);
      }
    } catch {
      // content_time not deployed yet (migration 0109): lessons and quizzes stay "not measured".
      (idx.unmeasured ??= new Set()).add(kind);
    }
  }
  return idx;
}

/** Minutes spent per item for one learner, aligned with `items`: null where time is not measured. */
export function minutesFor(idx: TimeIndex, userId: string, items: readonly Pick<PlanItem, "kind" | "id">[]): (number | null)[] {
  const m = idx.get(userId);
  return items.map(it => (timeMeasured(it, idx) ? Math.round(((m?.get(itemKey(it)) ?? 0) / 60) * 10) / 10 : null));
}
