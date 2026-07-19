# Infrastructure & Phase-1 Enablement

*What was built to make the platform production-deployable and to de-risk the biggest lift (Phase 1: accounts + a real database). Read alongside `PRODUCTION_READINESS_PLAN.md`.*

## What now exists in the repo

| Area | File(s) | Purpose |
|---|---|---|
| **Storage seam** | `src/lib/storage/keys.ts`, `backend.ts`, `progress.ts` | The single place localStorage is swapped for a server DB in Phase 1. All learner reads/writes funnel through the typed facade. |
| **DB schema** | `supabase/migrations/0002_app_progress.sql` | Postgres tables modeling the **actual shipped** data (rooms, dashboard sessions, scenario history, streaks, AI-usage) with owner-only RLS — mapped 1:1 to the facade. |
| **Env config** | `src/lib/config/env.ts`, `.env.example` | zod-validated, server-only env accessor; fails fast in prod on malformed config; documents every var. |
| **Rate-limit seam** | `src/lib/security/rateLimit.ts`, `src/middleware.ts` | `RateLimitStore` interface (in-memory now, Upstash-ready). Middleware calls only `checkRateLimit()`. |
| **CI/CD** | `.github/workflows/ci.yml` | lint · typecheck · build · dependency audit on every PR/push. |
| **Security (prior)** | `next.config.mjs`, `src/middleware.ts` | Security headers + CSP Report-Only + API rate limiting. See `SECURITY_PT_REPORT.md`. |

## The storage seam — how Phase 1 plugs in

Today every per-user read/write goes through `src/lib/storage/progress.ts`, backed by `localStorageBackend`. To move to the server:

1. **Auth + DB** — stand up Supabase (or Neon + Auth.js). Run `0001_init.sql` then `0002_app_progress.sql`.
2. **Remote backend** — implement a `StorageBackend` whose `get` reads an in-memory cache and whose `set` writes through to the API/DB.
3. **Hydration provider** — a `ProgressProvider` that, on login, loads the user's rows into that cache (async, once), then calls `setStorageBackend(remoteBackend)`.
4. **Done.** Because all facades already route through `backend`, **no UI call site changes.** The XP subsystem is already fully migrated as a working proof (see below).

### Migration status (learner data → facade)
- ✅ **XP (`soc_total_xp`)** — fully migrated: `RoomClient`, `EarnMoment`, dashboard `page.tsx`, `ScenarioClient`, `progress/page.tsx` all use `getTotalXp`/`addTotalXp`. Proves the seam end-to-end.
- ⬜ **Remaining (mechanical, same keys — safe to do incrementally):** `room_progress` (RoomClient/rooms page/progress), `soc_dashboard_sessions` (useLiveEvents/progress), `soc_scenario_history` (ScenarioClient/progress), `soc_company_cleared_v1`, `soc_streak_freeze_dates`. Facade methods already exist for all of them (`getRoomProgress`/`saveRoomProgress`, `getDashboardSessions`/`appendDashboardSession`, `getScenarioHistory`/`appendScenarioRecord`, `getClearedCompanies`/`addClearedCompany`, `getStreakFreezeDates`/`saveStreakFreezeDates`).
- **Admin/content keys** (`generated_*`, `admin_*`, `published_scenarios`) are staff tooling — a separate Phase-2 concern (content moves server-side behind a staff role), not per-learner data.

## Deploying — LIVE on Vercel (2026-07-19)

**Production URL:** https://soc-training-platform-jade.vercel.app
Vercel project `tal-ben-dosa/soc-training-platform`, connected to the GitHub repo (`TalBenDosa/SOC-Training-platform`) — **every push to the default branch now auto-deploys**. Production env vars set (3 Supabase + Anthropic/OpenAI keys, all encrypted). Security headers verified live on the production URL (HSTS, X-Frame-Options DENY, nosniff, CSP-Report-Only).

**Verified end-to-end on production:** a real signup on the live /signup page created the `auth.users` row, the trigger created `profiles` + `user_progress`, and the user was auto-signed-in (Confirm-email is OFF for the beta — see below). Test user deleted afterward.

Setup notes / follow-ups:
1. **"Confirm email" is currently OFF** in Supabase (Sign In / Providers → User Signups). Reason: Supabase's built-in email sender allows only ~2 emails/hour, which broke signups ("email rate limit exceeded"). Before public launch: set up custom SMTP (Postmark/Resend/SendGrid) in Supabase → Auth → Emails, then turn Confirm email back ON.
2. Supabase Auth **Site URL** = the production URL; **Redirect URLs** = production/** + localhost:3000/** (Auth → URL Configuration).
3. A Vercel CLI token (`claude-setup-cli`, scope TalBenDosa, expires 2026-07-26) lives in `.env.local` as `VERCEL_TOKEN`; revoke it in Vercel → Account Settings → Tokens if unneeded.
4. Add a custom domain in Vercel → Project → Domains when ready; TLS is automatic.
5. CI (`.github/workflows/ci.yml`) gates PRs; Vercel builds preview deploys per PR.
6. **Phase 0.7:** create an Upstash Redis DB, set `UPSTASH_REDIS_REST_*`, and implement `UpstashRateLimitStore` in `rateLimit.ts` (the only change needed for durable, cross-instance limiting).

## Auth & accounts — LIVE (Supabase Auth, email+password)

**Connected and verified end-to-end on 2026-07-19** against project `wrxhxtdllbctsawvewue` ("Hack The SOC Real"): a real signup through `/signup` created a row in `auth.users`, the `0003_auth_trigger.sql` trigger fired and created matching `profiles` + `user_progress` rows (confirmed via the PostgREST API), and the confirmation-email gate showed correctly. The test account was deleted after verification (cascaded cleanly). If no Supabase project is configured, every auth page still falls back gracefully to "Continue as guest" — verified separately.

**Gotcha for next time (cost ~30 min to diagnose):** Supabase's **"Direct connection"** string (`db.<ref>.supabase.co`) resolves **IPv6-only** — it will fail with a DNS/hostname-resolution error on any machine or network without IPv6 (common on Windows + typical ISPs). Always use the **Session pooler** connection string instead (`aws-0-<region>.pooler.supabase.com`, user `postgres.<ref>` not just `postgres`) for `DATABASE_URL` / migration pushes — it's IPv4-compatible. Get it from the project's green **Connect** button → Direct → Connection Method → **Session pooler**.

**Also note:** newer Supabase projects show **"Publishable key"** / **"Secret keys"** in Settings → API instead of the legacy **anon** / **service_role** names — they map 1:1 to `NEXT_PUBLIC_SUPABASE_ANON_KEY` / `SUPABASE_SERVICE_ROLE_KEY` respectively and work as drop-in values.

| Area | File(s) |
|---|---|
| Supabase clients | `src/lib/supabase/{config,client,server,middleware}.ts` |
| Auth state | `src/lib/auth/AuthContext.tsx` — `useAuth()` → `{ user, session, loading, authEnabled, signOut }` |
| Auth pages | `src/app/(auth)/{login,signup,reset-password,update-password}/page.tsx`, `src/app/auth/callback/route.ts` |
| Remote backend | `src/lib/storage/remoteBackend.ts` — the concrete `StorageBackend` the seam was built for; `ProgressProvider.tsx` hydrates it on sign-in and does a **one-time import of the guest's local progress into a brand-new account** |
| Nav | `Sidebar.tsx` shows the signed-in email + sign-out, or "Sign in", or "Guest — progress saved on this device" (no config) |
| Auto-provisioning | `supabase/migrations/0003_auth_trigger.sql` — creates `profiles` + `user_progress` rows on signup (required: `profiles.handle` is `unique not null`) |

### Two ways to make it live — both need one manual step I can't do for you

I can't create an external Supabase cloud account (account creation on a third-party service) **or** spin up the local Docker stack here (Docker Desktop isn't installed on this machine). Pick whichever fits:

#### Option A — Local demo, one command *(recommended for a throwaway demo; no cloud, no cost)*
1. Install **Docker Desktop** once — https://www.docker.com/products/docker-desktop/ — and start it.
2. Run **`npm run supabase:local`**. That's it — the script (`scripts/setup-local-supabase.mjs`) boots a full local Supabase (Postgres+Auth+Studio), **applies all three migrations in order automatically**, and writes the keys into `.env.local` for you.
3. `npm run dev` → `/signup` works immediately (local Supabase auto-confirms emails, so no email step). Tear down with `npx supabase stop`.

#### Option B — Cloud (no Docker needed)

1. **Create a Supabase project** at [supabase.com](https://supabase.com) (free tier is enough to start).
2. **Run the migrations, in order**, in the Supabase SQL Editor: `supabase/migrations/0001_init.sql` → `0002_app_progress.sql` → `0003_auth_trigger.sql`.
3. **Copy 3 values** from Supabase → Project Settings → API into `.env.local` (copy `.env.example` first): `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`.
4. **Restart the dev server** (env vars only load at boot) — signup/login go live immediately, no code changes needed.
5. **Optional, recommended for a smoother MVP:** in Supabase → Authentication → Providers → Email, you can toggle **"Confirm email" off** to let new users start immediately after signup instead of waiting on a confirmation email (fine for a beta; turn it back on before a public launch to stop throwaway-email signups).
6. **Before real users sign up:** Supabase's default outgoing email (used for confirmation/reset links) is low-volume and fine for testing, but for production add a custom SMTP provider (Postmark/Resend/SendGrid) in Supabase → Authentication → SMTP Settings, so confirmation emails don't land in spam or hit rate limits.

That's it — steps 1–4 are the entire path from "no accounts" to "people can register." Everything else (session handling, password reset, progress migration, RLS) is already built and will work the moment those 3 env vars are set.

## Known follow-ups (tracked in PRODUCTION_READINESS_PLAN.md)
- **Next 14 → 16** major upgrade (clears remaining dependency advisories; tighten CI audit to `--audit-level=high` after).
- **Auth on every write/LLM/admin route** (currently open — the rate limiter is the only gate).
- **`zod` request validation + size caps** on API routes (`env.ts` already uses zod; extend to request bodies).
- **Promote CSP** from Report-Only to enforcing with nonces.
