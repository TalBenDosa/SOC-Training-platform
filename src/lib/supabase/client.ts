"use client";
/**
 * Browser Supabase client — singleton, used by client components (auth forms,
 * the remote storage backend). Returns null when Supabase isn't configured so
 * callers can fall back to guest/localStorage mode instead of crashing.
 */
import { createBrowserClient } from "@supabase/ssr";
import type { SupabaseClient } from "@supabase/supabase-js";
import { supabaseUrl, supabaseAnonKey, isSupabaseConfigured } from "./config";

let client: SupabaseClient | null = null;

export function getSupabaseBrowserClient(): SupabaseClient | null {
  if (!isSupabaseConfigured) return null;
  if (!client) {
    client = createBrowserClient(supabaseUrl!, supabaseAnonKey!);
  }
  return client;
}
