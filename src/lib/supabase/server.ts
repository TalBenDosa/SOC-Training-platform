import "server-only";
/**
 * Server-side Supabase client — for Route Handlers and Server Components.
 * Reads/writes the auth cookie via Next's `cookies()` so the session survives
 * across requests. Returns null when Supabase isn't configured.
 */
import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import { supabaseUrl, supabaseAnonKey, isSupabaseConfigured } from "./config";

export async function getSupabaseServerClient() {
  if (!isSupabaseConfigured) return null;
  const cookieStore = await cookies();

  return createServerClient(supabaseUrl!, supabaseAnonKey!, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, options);
          }
        } catch {
          // Called from a Server Component (no response to attach cookies to).
          // Safe to ignore as long as middleware.ts also refreshes the session.
        }
      },
    },
  });
}
