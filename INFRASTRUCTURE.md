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

## Deploying (recommended path: Vercel)

1. Import the repo into **Vercel** (auto-detects Next.js).
2. Set env vars from `.env.example` in the Vercel project (Production + Preview). At minimum the app runs with none (stub content); add `ANTHROPIC_API_KEY` for real AI, and the Supabase/Auth vars once Phase 1 lands.
3. Add a custom domain; TLS is automatic.
4. CI (`.github/workflows/ci.yml`) gates PRs; Vercel builds preview deploys per PR.
5. **Phase 0.7:** create an Upstash Redis DB, set `UPSTASH_REDIS_REST_*`, and implement `UpstashRateLimitStore` in `rateLimit.ts` (the only change needed for durable, cross-instance limiting).

## Auth & accounts — now built (Supabase Auth, email+password)

The code side of Phase 1 is done: signup, login, password reset, session refresh, and the DB-backed storage backend all exist and build cleanly. **Nothing is live yet** because no Supabase project is connected — every auth page detects this and shows a graceful "Continue as guest" fallback (verified live: `/login` with no env configured renders "Accounts aren't set up yet" instead of crashing).

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
