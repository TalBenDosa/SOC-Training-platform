import "server-only";
/**
 * Service-role Supabase client — bypasses RLS. SERVER-ONLY, and never to be
 * imported into anything that reaches the browser bundle.
 *
 * Use for trusted server-side writes that must not be forgeable by a client:
 * today, appending to `public.audit_log` (which is locked to no client access
 * by migration 0007, so only this key can write it). Do NOT use it as a
 * convenience to skip RLS on ordinary user data — that would defeat the access
 * controls in migrations 0004/0005.
 *
 * Returns null when SUPABASE_SERVICE_ROLE_KEY is not configured, so callers must
 * degrade gracefully (e.g. audit logging falls back to stderr).
 */
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { supabaseUrl } from "./config";

let cached: SupabaseClient | null = null;

export function getSupabaseAdminClient(): SupabaseClient | null {
  if (cached) return cached;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceKey) return null;

  cached = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return cached;
}
