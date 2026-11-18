import "server-only";
/**
 * dashboard_shifts (0116): the server's record of one solo training, written only with the
 * service-role client by the /api/dashboard/shift routes and the incident-report grader.
 * Holds each dealt story's answer; nothing here is ever returned to the browser.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import type { OrgCompanyContent } from "@/lib/content/publicContent";
import { getSupabaseServerClient } from "@/lib/supabase/server";
import { isMissingSchema } from "@/lib/progress/record";
import type { ShiftStory, SoloDifficulty } from "./soloShift";

export interface ShiftRow {
  id: string;
  user_id: string;
  org_id: string | null;
  company_id: string;
  difficulty: SoloDifficulty;
  stories: ShiftStory[];
  started_at: string;
  ended_at: string | null;
  session_id: string | null;
}

const COLS = "id, user_id, org_id, company_id, difficulty, stories, started_at, ended_at, session_id";
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** A training is 30 minutes; a shift older than this is closed (a forgotten tab, a replayed request). */
export const SHIFT_MAX_AGE_MS = 3 * 60 * 60 * 1000;
/** More solo trainings than this in an hour is a script (the same bound 0085 keeps for session rows). */
export const SHIFTS_PER_HOUR = 30;

export class ShiftSchemaMissing extends Error {}

/** The learner's own shift, or null (unknown id, another user's, or too old to accept reports). */
export async function loadShift(admin: SupabaseClient, id: unknown, userId: string): Promise<ShiftRow | null> {
  if (typeof id !== "string" || !UUID.test(id)) return null;
  const { data, error } = await admin.from("dashboard_shifts").select(COLS).eq("id", id).eq("user_id", userId).maybeSingle();
  if (error) { if (isMissingSchema(error, "dashboard_shifts")) throw new ShiftSchemaMissing(); throw new Error(error.message); }
  if (!data) return null;
  const row = data as ShiftRow;
  if (Date.now() - Date.parse(row.started_at) > SHIFT_MAX_AGE_MS) return null;
  return { ...row, stories: Array.isArray(row.stories) ? row.stories : [] };
}

export async function shiftsInLastHour(admin: SupabaseClient, userId: string): Promise<number> {
  const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const { count, error } = await admin.from("dashboard_shifts").select("id", { count: "exact", head: true })
    .eq("user_id", userId).gte("started_at", since);
  if (error) { if (isMissingSchema(error, "dashboard_shifts")) throw new ShiftSchemaMissing(); throw new Error(error.message); }
  return count ?? 0;
}

export async function insertShift(admin: SupabaseClient, row: Omit<ShiftRow, "id" | "started_at" | "ended_at" | "session_id">): Promise<string> {
  const { data, error } = await admin.from("dashboard_shifts").insert(row).select("id").single();
  if (error) { if (isMissingSchema(error, "dashboard_shifts")) throw new ShiftSchemaMissing(); throw new Error(error.message); }
  return (data as { id: string }).id;
}

export async function saveStories(admin: SupabaseClient, id: string, stories: ShiftStory[]): Promise<void> {
  const { error } = await admin.from("dashboard_shifts").update({ stories }).eq("id", id);
  if (error) throw new Error(error.message);
}

/**
 * The story ids this learner met most recently, newest first: their recorded incidents (reported or
 * missed, any device) and the stories of their last trainings (a story dealt and abandoned still counts).
 */
export async function recentStoryIds(admin: SupabaseClient, userId: string): Promise<string[]> {
  const [inc, shifts] = await Promise.all([
    admin.from("dashboard_incidents").select("story_id, created_at").eq("user_id", userId)
      .not("story_id", "is", null).order("created_at", { ascending: false }).limit(60),
    admin.from("dashboard_shifts").select("stories, started_at").eq("user_id", userId)
      .order("started_at", { ascending: false }).limit(6),
  ]);
  const dated: { id: string; at: number }[] = [];
  for (const r of (inc.data ?? []) as { story_id: string | null; created_at: string }[]) {
    if (r.story_id) dated.push({ id: r.story_id, at: Date.parse(r.created_at) });
  }
  for (const s of (shifts.data ?? []) as { stories: ShiftStory[] | null }[]) {
    for (const st of Array.isArray(s.stories) ? s.stories : []) dated.push({ id: st.storyId, at: Date.parse(st.dealtAt) });
  }
  dated.sort((a, b) => b.at - a.at);
  const out: string[] = [];
  for (const d of dated) if (!out.includes(d.id)) out.push(d.id);
  return out.slice(0, 12);
}

/** A college-authored company the learner can see (the same published content the dashboard loads, read under their own RLS). */
export async function orgCompanyFor(companyId: string): Promise<OrgCompanyContent | null> {
  const supabase = await getSupabaseServerClient();
  if (!supabase) return null;
  const { data, error } = await supabase.from("content_companies").select("content").eq("status", "published");
  if (error || !data) return null;
  for (const row of data as { content: unknown }[]) {
    const c = (row.content ?? {}) as OrgCompanyContent;
    if (c?.profile?.id === companyId && Array.isArray(c.benignEvents) && c.story?.events) return c;
  }
  return null;
}
