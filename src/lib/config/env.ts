/**
 * Server-side environment configuration — validated once, typed everywhere.
 *
 * The app is designed to run WITHOUT the optional keys (routes fall back to stub
 * content when a provider key is absent), so this does NOT hard-crash on missing
 * values. Instead it validates the SHAPE of anything that is set, exposes a typed
 * `serverEnv`, and offers `requireEnv()` for the few code paths that genuinely
 * need a value. Import only from server code (route handlers, server components).
 */
import { z } from "zod";

if (typeof window !== "undefined") {
  // Never let secrets-bearing config be imported into a client bundle.
  throw new Error("src/lib/config/env.ts is server-only and must not be imported on the client.");
}

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),

  // Public app origin (used for absolute URLs, callbacks). Optional in dev.
  NEXT_PUBLIC_APP_URL: z.string().url().optional(),

  // ── Database (Supabase / Postgres) — Phase 1 ──
  NEXT_PUBLIC_SUPABASE_URL: z.string().url().optional(),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().min(1).optional(),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1).optional(),
  DATABASE_URL: z.string().url().optional(),

  // ── Auth (Auth.js / NextAuth) — Phase 1 ──
  AUTH_SECRET: z.string().min(16).optional(),

  // ── LLM providers ──
  ANTHROPIC_API_KEY: z.string().startsWith("sk-ant-").optional(),
  ANTHROPIC_MODEL: z.string().optional(),
  OPENAI_API_KEY: z.string().startsWith("sk-").optional(),

  // ── Durable rate-limit store (replaces in-memory) — Phase 0.7 ──
  UPSTASH_REDIS_REST_URL: z.string().url().optional(),
  UPSTASH_REDIS_REST_TOKEN: z.string().min(1).optional(),

  // ── Observability — Phase 4 ──
  SENTRY_DSN: z.string().url().optional(),
});

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
  // A malformed value (e.g. a key with the wrong prefix) is a real config error.
  // Log it clearly; in production, fail fast so a broken deploy doesn't silently
  // run with mis-set secrets.
  console.error("❌ Invalid environment configuration:", parsed.error.flatten().fieldErrors);
  if (process.env.NODE_ENV === "production") {
    throw new Error("Invalid environment configuration — see logs above.");
  }
}

export const serverEnv = (parsed.success ? parsed.data : schema.parse({ NODE_ENV: "development" }));

/** Fetch a required env var or throw a clear error (use in routes that need it). */
export function requireEnv<K extends keyof typeof serverEnv>(key: K): NonNullable<(typeof serverEnv)[K]> {
  const value = serverEnv[key];
  if (value === undefined || value === "") {
    throw new Error(`Missing required environment variable: ${String(key)}`);
  }
  return value as NonNullable<(typeof serverEnv)[K]>;
}

/** True when at least one LLM provider is configured. */
export const hasLlmProvider = Boolean(serverEnv.ANTHROPIC_API_KEY || serverEnv.OPENAI_API_KEY);
/** True when a durable rate-limit store is configured (else in-memory fallback). */
export const hasDurableRateLimit = Boolean(serverEnv.UPSTASH_REDIS_REST_URL && serverEnv.UPSTASH_REDIS_REST_TOKEN);
