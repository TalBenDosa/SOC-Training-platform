import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";

/** org-media keys: <orgId>/<kind>/<uuid>.<ext> — the kinds /api/org/media/sign mints. */
export const MEDIA_KINDS = ["pdf", "pptx", "video"] as const;
const BUCKET = "org-media";
/** A signed upload URL lives ~2 h; an object older than this with no row was abandoned. */
export const ORPHAN_AGE_MS = 6 * 3600 * 1000;
const PAGE = 100;

/**
 * Delete org-media objects that were uploaded through a signed URL but never
 * finalized (no org_resources row) — QA phase 6, SEC-17. Without this, a looped
 * sign → upload → never-finalize filled storage with up to 200 MB a time,
 * forever (never served, but paid for). Runs from the daily cron.
 */
export async function purgeOrphanUploads(admin: SupabaseClient, now = Date.now()): Promise<{ scanned: number; deleted: number; errors: number }> {
  let scanned = 0, deleted = 0, errors = 0;
  const { data: orgs, error: orgErr } = await admin.from("organizations").select("id");
  if (orgErr || !orgs) return { scanned, deleted, errors: 1 };

  for (const { id: orgId } of orgs as { id: string }[]) {
    const { data: rows, error: rowErr } = await admin.from("org_resources").select("storage_key").eq("org_id", orgId);
    if (rowErr) { errors++; continue; }                      // never delete without knowing what's referenced
    const referenced = new Set((rows ?? []).map(r => String((r as { storage_key: string }).storage_key)));
    for (const kind of MEDIA_KINDS) {
      const prefix = `${orgId}/${kind}`;
      for (let offset = 0; ; offset += PAGE) {
        const { data: objs, error } = await admin.storage.from(BUCKET).list(prefix, { limit: PAGE, offset, sortBy: { column: "name", order: "asc" } });
        if (error) { errors++; break; }
        if (!objs?.length) break;
        scanned += objs.length;
        const stale = objs
          .filter(o => o.id)                                   // files, not folder placeholders
          .filter(o => !referenced.has(`${prefix}/${o.name}`))
          .filter(o => { const t = Date.parse(o.created_at ?? ""); return Number.isFinite(t) && now - t > ORPHAN_AGE_MS; })
          .map(o => `${prefix}/${o.name}`);
        if (stale.length) {
          const { error: delErr } = await admin.storage.from(BUCKET).remove(stale);
          if (delErr) errors++; else { deleted += stale.length; offset -= stale.length; }
        }
        if (objs.length < PAGE) break;
      }
    }
  }
  return { scanned, deleted, errors };
}
