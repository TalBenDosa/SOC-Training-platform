# Live Penetration Test — HACK THE SOC (production)

**Target:** https://soc-training-platform-jade.vercel.app (live Vercel deployment, Supabase backend)
**Date:** 2026-07-19  **Type:** grey-box (source + live black-box), authorized by the owner.
**Context:** First PT against the *live* target. The app was deployed and the LLM API keys
were pushed to production earlier the same day, which is what turned two latent code issues
into active, exploitable exposures.

---

## Executive summary

| # | Finding | Severity | Status |
|---|---|---|---|
| F1 | Every LLM-calling API route was reachable with **no authentication** → anonymous financial-DoS (drain the AI budget) | **Critical** | ✅ Fixed & deployed |
| F2 | `profiles` table **world-readable** via anon key → user enumeration + admin-account disclosure | **High** | ⚠️ Fix ready — 1 SQL paste needed |
| F3 | Rate limiting is in-memory (per-instance) — weak on serverless | Medium | ⬜ Documented follow-up |
| F4 | CSP is Report-Only (and permits `unsafe-inline`/`unsafe-eval`) | Low | ⬜ Documented follow-up |
| — | Secrets in client bundle, verb tampering, path traversal, `user_progress` RLS | — | ✅ Tested — all clean |

---

## F1 — Unauthenticated access to paid-LLM routes  ·  CRITICAL  ·  FIXED

**What:** All 11 API routes that call a paid LLM (Anthropic/OpenAI) executed the model call
with no auth check. A live probe of `POST /api/scenarios/generate` with an empty body returned
`200` and triggered a real Anthropic streaming call.

**Impact:** With production API keys live, any anonymous internet user (or a script) could issue
LLM calls on the owner's account. The only prior control was a per-IP in-memory rate limit
(10/min) — trivially bypassed with rotating IPs, and reset on every serverless cold start. Realistic
exposure: hundreds of dollars/day of API spend, plus a prompt-injection surface.

**Root cause:** routes read `process.env.ANTHROPIC_API_KEY` and called the model directly; the key
being absent was the *only* thing that had ever gated them. Pushing the key to prod removed that gate.

**Fix (shipped):** new fail-closed guard `src/lib/auth/apiGuard.ts`, applied to all 11 routes:
- **Content-authoring / admin (7)** → `requireAdmin()`: `401` if not signed in, `403` if signed in
  but `role != 'admin'`. Routes: `admin/validate-logs`, `scenarios/generate`,
  `lessons/{generate,generate-stream,validate,import-pptx,export-pptx}`, `quizzes/generate`.
- **Student consumption (4)** → paid LLM path gated behind a signed-in user; guests fall back to the
  existing zero-cost heuristic/stub (no UX regression). Routes: `dashboard/{ai-grade,incident-report}`,
  `scenarios/[slug]/grade`, `lessons/[slug]`.

Auth uses `supabase.auth.getUser()` (validates the JWT server-side) rather than `getSession()`, so a
forged/expired cookie cannot impersonate a user or an admin.

**Verification:** local — unauth `POST` to the 7 admin routes → `401`; guest `POST` to a student route
→ `200` via heuristic (no LLM spend). `tsc` + production `build` clean. Re-probed on production after
deploy (see foot of file).

---

## F2 — `profiles` table world-readable  ·  HIGH  ·  FIX READY (needs 1 SQL paste)

**What:** `0001_init.sql` shipped `create policy "profiles read" ... for select using (true)`. A live
probe with the public **anon** key read the full `profiles` table, returning every row's `id`, `handle`
and **`role`** — including which account is `admin`.

**Impact:** user enumeration + disclosure of the admin account's user id and role. No secret is leaked,
but it hands an attacker reconnaissance and a specific high-value target. (`user_progress` was tested the
same way and correctly returned `[]` — its owner-only RLS works.)

**Fix:** `supabase/migrations/0004_tighten_profiles_rls.sql` replaces the read policy with owner-only
(`auth.uid() = id`). This does not break the admin-role guard (a user still reads their *own* role).
**Action required (SQL execution is out of my permission scope):** paste the file's contents into the
Supabase SQL Editor and Run, or run `supabase db push`.

---

## F3 — In-memory rate limiting  ·  MEDIUM  ·  follow-up

Counters live in per-instance memory (`src/lib/security/rateLimit.ts`), so on Vercel they are per-lambda
and reset on cold start — the effective limit is much looser than 10/min. With F1 fixed the blast radius
is now limited to authenticated users, but a durable store keyed by user id + IP (Upstash Redis / Vercel
KV) is still needed before scale. The `RateLimitStore` seam already exists for a drop-in `UpstashRateLimitStore`.

## F4 — CSP Report-Only  ·  LOW  ·  follow-up

`Content-Security-Policy-Report-Only` is set but not enforced, and the policy allows `unsafe-inline` /
`unsafe-eval`. Promoting to enforcing without first moving to nonce-based inline scripts would either be
security theater (unsafe-* still allowed) or break the app. Correct path: nonce the inline scripts, then
flip to enforcing — a deliberate change, not a one-liner. Other headers (HSTS w/ preload, X-Frame-Options
DENY, nosniff, Referrer-Policy, Permissions-Policy) are present and correct.

---

## Tested and clean

- **Secrets in client bundle** — no `service_role`, `sk-…`, or `vcp_…` token in served HTML/JS. ✅
- **Verb tampering** — `GET/PUT/DELETE` on POST-only routes → `405`. ✅
- **Path traversal** — `GET /api/lessons/..%2f..%2fetc%2fpasswd` → `400` (slug-format rejected). ✅
- **`user_progress` RLS** — anon read → `[]` (owner-only enforced). ✅
- **Secrets in git history** — only `.env.example` tracked; `.env.local` git-ignored. ✅

## Residual / recommended (owner actions)

1. Apply F2 migration (1 SQL paste).
2. Set hard **monthly spend caps** in the Anthropic and OpenAI consoles as defense-in-depth behind F1.
3. Rotate the DB password (was visible in an earlier session) and the `VERCEL_TOKEN` after setup.
4. Schedule F3 (durable rate limit) and F4 (CSP nonces) before public scale.

---

### Production re-verification (post-deploy) — CONFIRMED
Re-probed https://soc-training-platform-jade.vercel.app after the F1 deploy went Ready:
- `POST` (unauth) to all 7 content/admin routes → **401** (was 200 pre-fix).
- `GET /api/admin/validate-logs` (unauth) → **401**.
- `POST /api/dashboard/incident-report` (guest) → **200** via heuristic (no LLM spend) — UX intact.

F1 closed on production. F2 pending the owner's SQL paste (0004 migration).
