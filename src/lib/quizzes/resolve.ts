import "server-only";
/**
 * Resolve a quiz slug to the FULL, gradable Quiz (answer key included) on the
 * server — the single source of truth for `POST /api/quizzes/[slug]/grade`.
 *
 * Mirrors `getEffectiveRoom` (src/lib/rooms/resolve.ts):
 *   1. Static built-ins first (ALL_QUIZZES — in-memory, no answer split needed
 *      because they never cross to the client except via sanitizeQuiz).
 *   2. Otherwise an org-authored DB quiz (content_quizzes, migration 0040): read
 *      it with the service role and re-assert the org boundary (service role
 *      bypasses RLS, so a row is resolvable only if global or the caller's org).
 *
 * The resolved Quiz carries the answer key; only the grade route reads it, and
 * it returns a question's answer solely once that question has been answered.
 */
import { getQuiz, type Quiz } from "@/lib/quizzes/data";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

export async function resolveGradableQuiz(slug: string, orgId: string | null): Promise<Quiz | null> {
  const builtin = getQuiz(slug);
  if (builtin) return builtin;

  // Org-authored quiz ids are namespaced `org-…` (see orgContent.ts); anything
  // else that isn't a built-in simply doesn't exist.
  if (!slug.startsWith("org-")) return null;

  const admin = getSupabaseAdminClient();
  if (!admin) return null;

  const { data: row } = await admin
    .from("content_quizzes")
    .select("id, org_id, status, content")
    .eq("id", slug)
    .maybeSingle();
  if (!row) return null;
  if (row.status !== "published") return null;
  // Re-assert the org boundary: a global row (org_id null) is fine, otherwise it
  // must belong to the caller's org.
  if (row.org_id !== null && row.org_id !== orgId) return null;

  const content = (row.content ?? {}) as Partial<Quiz>;
  if (!Array.isArray(content.questions) || content.questions.length === 0) return null;
  return content as Quiz;
}
