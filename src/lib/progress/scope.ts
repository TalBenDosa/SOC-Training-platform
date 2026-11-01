import "server-only";
/**
 * Scope of the learner's self view: their own rows in their CURRENT organisation only.
 * Iron rule (Tal): nothing from one organisation or environment shows in another, so a
 * learner who moved colleges sees only what they did in this one.
 *
 * graded_first_answers gained org_id in 0101. Rows written before it (or on a database
 * without the column) are matched by time instead: answered on or after the learner
 * joined this org, the same rule the org-admin student page uses.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import type { AuthedUser } from "@/lib/auth/apiGuard";
import { isMissingSchema } from "./record";

export interface FirstAnswerFull {
  kind: "quiz" | "lesson" | "scenario"; content_id: string; question_id: string; correct: boolean; created_at: string | null; answer?: unknown;
}

export interface SelfScope {
  orgId: string | null;
  joinedAt: string;
  readFirsts: (withAnswer?: boolean) => Promise<FirstAnswerFull[]>;
}

/** A query builder that can be filtered by org (PostgREST builders all can). */
interface OrgFilterable { eq(column: string, value: string): unknown; is(column: string, value: null): unknown }

/** Filters any PostgREST query to the scope's org. Typed loosely on purpose: the builder's
 *  own generics are too deep for TypeScript to re-derive through a helper. */
export function scopeOrg<Q>(q: Q, scope: { orgId: string | null }): Q {
  const b = q as unknown as OrgFilterable;
  return (scope.orgId ? b.eq("org_id", scope.orgId) : b.is("org_id", null)) as Q;
}

export async function loadSelfScope(admin: SupabaseClient, user: AuthedUser): Promise<SelfScope> {
  const orgId = user.orgId;
  let joinedAt = "1970-01-01T00:00:00Z";
  if (orgId) {
    const { data } = await admin.from("org_members").select("joined_at").eq("org_id", orgId).eq("user_id", user.id).maybeSingle();
    if (data?.joined_at) joinedAt = data.joined_at as string;
  }
  const readFirsts = async (withAnswer = false): Promise<FirstAnswerFull[]> => {
    const cols = `kind, content_id, question_id, correct, created_at${withAnswer ? ", answer" : ""}`;
    const base = () => admin.from("graded_first_answers").select(cols).eq("user_id", user.id).limit(5000);
    if (!orgId) {
      const { data } = await base().gte("created_at", joinedAt);
      return (data ?? []) as unknown as FirstAnswerFull[];
    }
    const res = await base().or(`org_id.eq.${orgId},and(org_id.is.null,created_at.gte."${joinedAt}")`);
    if (!res.error) return (res.data ?? []) as unknown as FirstAnswerFull[];
    if (!isMissingSchema(res.error, "org_id")) { console.error("[self scope] first answers read failed:", res.error.message); return []; }
    const { data } = await base().gte("created_at", joinedAt);
    return (data ?? []) as unknown as FirstAnswerFull[];
  };
  return { orgId, joinedAt, readFirsts };
}
