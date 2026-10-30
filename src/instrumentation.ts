/**
 * Server start-up hook (Next.js runs `register()` once per server instance).
 *
 * src/lib/config/env.ts validated the environment with zod and was written to
 * fail fast in production on malformed config — but nothing imported it, so it
 * never ran and every route read `process.env` unchecked. Importing it here
 * makes the validation run at boot on the Node runtime.
 *
 * DELIBERATE: a validation failure is logged, not rethrown. env.ts throws in
 * production on any malformed value, and the live deployment's variables have
 * never been checked against the schema — turning this on as fail-fast could
 * take the site down on a value that works today (e.g. a non-URL
 * NEXT_PUBLIC_APP_URL). Once the start-up logs show no "Invalid environment
 * configuration" line, set ENV_VALIDATION_STRICT=1 to make it fatal.
 */
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  try {
    await import("@/lib/config/env");
  } catch (err) {
    console.error("[instrumentation] environment validation failed:", err instanceof Error ? err.message : err);
    if (process.env.ENV_VALIDATION_STRICT === "1") throw err;
  }
}
