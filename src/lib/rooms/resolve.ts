import "server-only";
import type { Room } from "@/data/rooms";
import { ROOMS } from "@/data/rooms";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { recombineRoom } from "@/lib/rooms/authored";

/**
 * Resolve a room id to a full, gradable Room — the single entry point used by
 * BOTH the play page and the task-submit route, so org-authored rooms grade
 * through the same server-side path as the static ones.
 *
 *  1. Static built-ins first (ROOMS array — in-memory).
 *  2. Otherwise an org-authored DB room: load its client-safe projection
 *     (content_rooms) + answer key (content_room_keys, service-role only) and
 *     recombine them in server memory, re-asserting the org boundary (the
 *     service role bypasses RLS: resolvable only if global or the caller's org).
 *
 * The recombined Room carries the answer key; the play page runs sanitizeRoom
 * over it before it crosses to the client, and the submit route grades against
 * it in full.
 */
export async function getEffectiveRoom(roomId: string, orgId: string | null): Promise<Room | null> {
  const staticRoom = ROOMS.find(r => r.id === roomId);
  if (staticRoom) return staticRoom;

  if (!roomId.startsWith("org-")) return null;

  const admin = getSupabaseAdminClient();
  if (!admin) return null;

  const { data: row } = await admin
    .from("content_rooms")
    .select("id, org_id, status, content")
    .eq("id", roomId)
    .maybeSingle();
  if (!row) return null;
  if (row.org_id !== null && row.org_id !== orgId) return null;

  const content = (row.content ?? {}) as Record<string, unknown>;
  if (content.kind !== "authored") return null;

  const { data: keyRow } = await admin
    .from("content_room_keys")
    .select("answer_key")
    .eq("id", roomId)
    .maybeSingle();

  return recombineRoom(content, (keyRow?.answer_key ?? {}) as Record<string, unknown>);
}
