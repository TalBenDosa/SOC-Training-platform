/**
 * Whether Supabase is actually configured. Every client factory in this folder
 * checks this first so the app degrades gracefully — same "runs without the
 * key, falls back to a stub" pattern already used for ANTHROPIC_API_KEY /
 * OPENAI_API_KEY (see src/lib/config/env.ts). Signed-out/guest use of the app
 * (localStorage progress, no account) keeps working with zero config.
 */
export const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
export const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);
