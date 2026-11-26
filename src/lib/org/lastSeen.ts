/**
 * Server-side reads behind "last seen": the sign-in and session renewal of an organisation's
 * members (org_member_last_seen, 0123), their presence days (user_presence_days, 0123) and the
 * dated records that no roster read before (lesson time, library reads, film playback).
 *
 * Every read is pinned to ONE organisation, and every one is optional: on a database that does
 * not have the migration yet, or on a failed read, the caller gets an empty result and "last
 * seen" falls back to the learning records alone. Never throws.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import type { PresenceDay, SeenSources } from "./activity";

type Admin = SupabaseClient;
const MISSING = /42883|42P01|PGRST20[25]|does not exist|could not find/i;
const PAGE = 1000;

function warn(label: string, error: { code?: string; message: string } | null) {
  if (error && !MISSING.test(`${error.code ?? ""} ${error.message}`)) console.error(`[last seen] ${label}:`, error.message);
}

/** Pages through a query (PostgREST caps a read at 1000 rows). Returns what it got on an error. */
async function pages<T>(label: string, run: (from: number, to: number) => PromiseLike<{ data: unknown; error: { code?: string; message: string } | null }>, max = 20_000): Promise<T[]> {
  const out: T[] = [];
  try {
    for (let from = 0; from < max; from += PAGE) {
      const { data, error } = await run(from, from + PAGE - 1);
      if (error) { warn(label, error); break; }
      const rows = (data ?? []) as T[];
      out.push(...rows);
      if (rows.length < PAGE) break;
    }
  } catch (e) {
    console.error(`[last seen] ${label}:`, e instanceof Error ? e.message : e);
  }
  return out;
}

/** Sign-in and session renewal per member of the organisation. Empty before migration 0123. */
export async function loadOrgSeen(admin: Admin, orgId: string): Promise<Map<string, { last_sign_in_at: string | null; last_session_at: string | null }>> {
  const rows = await pages<{ user_id: string; last_sign_in_at: string | null; last_session_at: string | null }>(
    "org_member_last_seen", (f, t) => admin.rpc("org_member_last_seen", { p_org: orgId }).order("user_id").range(f, t));
  return new Map(rows.map(r => [r.user_id, { last_sign_in_at: r.last_sign_in_at, last_session_at: r.last_session_at }]));
}

/** Presence days of the organisation (or of one member) for the last `days` days. */
export async function loadPresence(admin: Admin, orgId: string, opts: { userId?: string; days?: number } = {}): Promise<Map<string, PresenceDay[]>> {
  const since = new Date(Date.now() - (opts.days ?? 30) * 86_400_000).toISOString().slice(0, 10);
  const rows = await pages<PresenceDay & { user_id: string }>("presence", (f, t) => {
    let q = admin.from("user_presence_days").select("user_id, day, first_seen_at, last_seen_at, active_seconds, visits").eq("org_id", orgId).gte("day", since);
    if (opts.userId) q = q.eq("user_id", opts.userId);
    return q.order("user_id").order("day").range(f, t);
  });
  const by = new Map<string, PresenceDay[]>();
  for (const { user_id, ...p } of rows) { const l = by.get(user_id); if (l) l.push(p); else by.set(user_id, [p]); }
  return by;
}

/**
 * Dated records of things a learner does that leave no room, scenario or shift row: time on a
 * lesson or a quiz (0109), a library lesson marked as read (0111) and film playback (0117, last
 * 30 days). Per user, for the organisation or for one member.
 */
export async function loadExtraActivity(admin: Admin, orgId: string, userId?: string): Promise<Map<string, string[]>> {
  const since = new Date(Date.now() - 30 * 86_400_000).toISOString();
  type Row = { user_id: string; at: string | null };
  const read = (table: string, col: string, recentOnly: boolean, order: string[]) => pages<Row>(table, (f, t) => {
    let q = admin.from(table).select(`user_id, at:${col}`).eq("org_id", orgId);
    if (userId) q = q.eq("user_id", userId);
    if (recentOnly) q = q.gte(col, since);
    for (const o of order) q = q.order(o);
    return q.range(f, t);
  });
  const [time, reads, films] = await Promise.all([
    read("content_time", "updated_at", false, ["user_id", "kind", "item_id"]),
    read("library_reads", "read_at", false, ["id"]),
    read("film_playback_events", "created_at", true, ["id"]),
  ]);
  const by = new Map<string, string[]>();
  for (const r of [...time, ...reads, ...films]) {
    if (!r.at) continue;
    const l = by.get(r.user_id);
    if (l) l.push(r.at); else by.set(r.user_id, [r.at]);
  }
  return by;
}

/** Everything known about when the members of an organisation were last seen. */
export async function loadSeenSources(admin: Admin, orgId: string, userId?: string): Promise<{ seen: Map<string, SeenSources>; extra: Map<string, string[]> }> {
  const [signs, presence, extra] = await Promise.all([loadOrgSeen(admin, orgId), loadPresence(admin, orgId, { userId }), loadExtraActivity(admin, orgId, userId)]);
  const seen = new Map<string, SeenSources>();
  for (const id of new Set([...signs.keys(), ...presence.keys()])) {
    if (userId && id !== userId) continue;
    seen.set(id, { ...signs.get(id), presence: presence.get(id) ?? [] });
  }
  return { seen, extra };
}
