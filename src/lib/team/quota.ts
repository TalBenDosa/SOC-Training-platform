/**
 * How many team exercises an organization may run (organizations.team_session_limit, 0099).
 * Team Training is sold as a premium, limited experience (Tal, 2026-10-18): NULL = unlimited,
 * 0 = none, N = N exercises. An exercise counts once it STARTS, so an abandoned lobby is free.
 */
import type { SupabaseClient } from "@supabase/supabase-js";

export interface TeamQuota { limit: number | null; used: number; remaining: number | null }

/** From a form / API value: undefined = not sent, "" / null = unlimited, else a whole number ≥ 0. */
export function sanitizeTeamLimit(v: unknown): number | null | undefined | "invalid" {
  if (v === undefined) return undefined;
  if (v === null || v === "") return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n) || n > 100000) return "invalid";
  return n;
}

export function quotaOf(limit: number | null | undefined, used: number): TeamQuota {
  const l = limit == null ? null : limit;
  return { limit: l, used, remaining: l == null ? null : Math.max(0, l - used) };
}

/** True when the organization has no team exercise left. */
export const quotaExhausted = (q: TeamQuota) => q.remaining != null && q.remaining <= 0;

export function quotaMessage(q: TeamQuota): string {
  if (q.limit === 0) return "Team training isn't part of your organization's plan. Contact HACK THE SOC to add team exercises.";
  return `Your organization has used all ${q.limit} of its team exercises. Contact HACK THE SOC to add more.`;
}

/** The organization's quota and how many team exercises it has started. */
export async function teamQuotaFor(admin: SupabaseClient, orgId: string): Promise<TeamQuota> {
  const [{ data: org, error: orgErr }, { count, error: cntErr }] = await Promise.all([
    admin.from("organizations").select("team_session_limit").eq("id", orgId).maybeSingle(),
    admin.from("team_sessions").select("id", { count: "exact", head: true }).eq("org_id", orgId).not("started_at", "is", null),
  ]);
  if (orgErr) throw new Error(`team quota: ${orgErr.message}`);
  if (cntErr) throw new Error(`team quota count: ${cntErr.message}`);
  return quotaOf((org as { team_session_limit?: number | null } | null)?.team_session_limit ?? null, count ?? 0);
}
