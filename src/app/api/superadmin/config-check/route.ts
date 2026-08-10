import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";

/**
 * TEMPORARY diagnostic — remove once PRIVACY_CONTACT_EMAIL is confirmed live.
 *
 * Added because /privacy kept serving its course-administrator fallback after
 * the variable was set in the host dashboard, and three plausible causes could
 * not be told apart from outside: a stray space in the NAME, an unsaved change,
 * or a wrong prefix. All three look identical in the dashboard and identical on
 * the page.
 *
 * WHAT IT DELIBERATELY DOES NOT DO: return the value of anything. It reports
 * matching variable NAMES and a presence boolean. Names are JSON-encoded so a
 * trailing space shows up as "PRIVACY_CONTACT_EMAIL " instead of rendering
 * invisibly — which is the single most likely cause and the one a dashboard
 * cannot show you.
 *
 * Super-admin only. Even so, keep the surface narrow: the name filter is a
 * fixed pattern, not a caller-supplied one, so this can never be turned into a
 * general "list the environment" endpoint.
 */
export const dynamic = "force-dynamic";

// Fixed, not caller-controlled — see the doc comment.
const NAME_PATTERN = /privacy|contact/i;

export async function GET() {
  const gate = await requireSuperAdmin("config.check");
  if ("error" in gate) return gate.error;

  const raw = process.env.PRIVACY_CONTACT_EMAIL;
  const trimmed = raw?.trim();

  return NextResponse.json({
    // What the page actually branches on.
    renders_mailto: Boolean(trimmed),

    privacy_contact_email: {
      defined: raw !== undefined,
      // Distinguishes "not set at all" from "set to empty/whitespace", which
      // produce the same fallback but need different fixes.
      empty_or_whitespace: raw !== undefined && !trimmed,
      length: raw?.length ?? 0,
      // Value is never returned. The domain alone is enough to confirm the
      // right address landed without publishing it here.
      domain: trimmed ? trimmed.split("@")[1] ?? "(no @ in value)" : null,
    },

    // The decisive bit: every env name that looks related, JSON-encoded so
    // stray whitespace is visible. An exact-name mismatch shows up here.
    matching_env_names: Object.keys(process.env)
      .filter(k => NAME_PATTERN.test(k))
      .sort()
      .map(k => JSON.stringify(k)),

    // Email delivery config — the definitive answer to "does PRODUCTION have
    // Resend?" Presence only, never the key value. If email_sends_enabled is
    // false, transactional emails (org welcome, admin invite) are SKIPPED —
    // Supabase auth emails (password reset) are separate and unaffected.
    email: {
      email_sends_enabled: Boolean(process.env.RESEND_API_KEY?.trim()),
      resend_api_key_set: Boolean(process.env.RESEND_API_KEY?.trim()),
      email_from_set: Boolean(process.env.EMAIL_FROM?.trim()),
      email_from_value: process.env.EMAIL_FROM?.trim() || "(unset → default onboarding@resend.dev)",
      email_env_names: Object.keys(process.env)
        .filter(k => /resend|email|smtp|mail/i.test(k))
        .sort()
        .map(k => JSON.stringify(k)),
    },

    deployment: {
      vercel_env: process.env.VERCEL_ENV ?? "(not on vercel)",
      commit: process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7) ?? "(unknown)",
    },
  });
}
