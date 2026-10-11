# Backend End-to-End Test & Security Audit

**Date:** 2026-08-05  ·  **Scope:** the entire backend of HACK THE SOC — DB schema, RLS, functions, triggers, guards, enrollment, licensing, purge, and all 25 API routes.  ·  **Method:** an automated backend test against the **real migrations** (in-memory Postgres / PGlite) + two independent audit passes (API layer, DB layer), with every high/critical finding **re-confirmed by direct execution** before being written down.

---

## 1. What was tested & how

| Layer | Harness | Result |
|---|---|---|
| DB schema, RLS, functions, triggers, guards, isolation, purge, licensing | `scripts/test-backend-e2e.mjs` (PGlite, real migrations 0001–0016) | **65 / 65 checks pass** |
| Two-college isolation (regression) | `scripts/test-multitenancy-local.mjs` | 25 / 25 pass |
| 25 API routes (guards, middleware, claims, rate-limit) | manual audit + code trace | 8 findings |
| DB migrations / RLS / functions | manual audit + PGlite confirmation | 8 findings |
| Fixes (0016 + code) | tsc clean · e2e 65/65 · prod-state PGlite confirmation | verified |

`test-backend-e2e.mjs` runs with **no Docker/Supabase** — it shims Supabase auth (`auth.users`, `auth.uid()`, `auth.jwt()`, the four roles, default privileges) and applies every migration in `supabase/migrations/` in order, then exercises:

- **A) Schema & RLS enablement** — RLS on all 10 tenant tables; ≥1 policy each; `org_id` on 9 tables.
- **B) Functions** — `handle_available`, `attach_member_if_seat_available` (seat cap + re-add), `find_user_id_by_email`, `resolve_invitation` (valid/expired), `expire_due_orgs`.
- **C) Triggers** — `handle_new_user` (invite / domain / default / full-org-fails), `recompute_user_xp` (room + scenario), the privileged-column guard, `touch_updated_at`.
- **D) RLS isolation** — two colleges; A sees only its own rows/org/members; cannot read or write into B; cannot read `invitations` / `audit_log`.
- **E) `purge_org`** — deletes all per-tenant data, re-homes accounts to internal, refuses to purge the internal org.
- **F) Licensing** — the access-token hook stamps `org_active` / `org_name` / `org_role` correctly for suspended vs active orgs.
- **G) Security-audit fixes (0016)** — leaderboard gone; content tables locked; roster read-gated; reactivation seat check; purge survives audit rows.

---

## 2. Gaps found (prioritized) & status

Severity reflects the **production** state (migrations 0001–0014 applied via the PART bundles; **0015 deferred** because the project is on the Supabase free plan — no backups — so its `DROP TABLE`/`DROP VIEW` were held back).

### 🔴 CRITICAL

| ID | Gap | Confirmed | Fix | Status |
|---|---|---|---|---|
| **C1** | `public.leaderboard` view ran `security_invoker=OFF` and kept default grants → **anonymous, cross-tenant** read of every user's id/handle/rank/xp across every org. A live tenant-isolation break (0015 would have dropped it, but 0015 is deferred). | ✅ anon SELECT returned cross-org rows | `0016`: `drop view leaderboard` (don't wait for 0015) | **Fixed in 0016** |

### 🟠 HIGH

| ID | Gap | Confirmed | Fix | Status |
|---|---|---|---|---|
| **H1** | 0001 content tables (`learning_paths`, `modules`, `lessons`, `scenarios`, `badges`) had **no RLS** and kept default anon/authenticated grants → anon DML. App-unused, but writable by the public. | ✅ RLS=false; anon INSERT passed the permission gate (failed only on NOT NULL) | `0016`: enable RLS + revoke grants (guarded by `to_regclass`) | **Fixed in 0016** |
| **API#1** | `GET /api/lessons/[slug]` makes a paid Anthropic call but wasn't in the middleware `EXPENSIVE` list → the only student-reachable paid route escaping both the 10/min IP cap **and** the 60/min per-org LLM budget. | ✅ path-match trace | `middleware.ts`: add `/api/lessons/` prefix | **Fixed (code)** |

### 🟡 MEDIUM

| ID | Gap | Confirmed | Fix | Status |
|---|---|---|---|---|
| **API#2** | `POST /api/scenarios/[slug]/grade` returned the full answer key (`correctAnswer` + `explanation`) and debrief (`narrative`/`objectives`/`killchain`) for **any** submission — a student could POST an empty body and harvest everything, defeating the no-hints `GET`. | ✅ code trace (GET strips these; grade did not) | grade route: reveal a question's answer only if it was **answered**; release the debrief only on a genuine attempt (all answered + real report) | **Fixed (code)** |
| **M3** | `org_members` read policy had no role gate → any **student** could enumerate the full class roster (every classmate's `user_id` + `role`). | ✅ policy read | `0016`: gate roster reads to `org_admin`/`instructor`; students read only their own row | **Fixed in 0016** |
| **API#3** | Invite-creation (`/api/org/invites`, `/api/superadmin/orgs/[id]/invites`) had no cap on the `emails[]` array → an org-admin could trigger a huge insert + mass-email fan-out (cost + sender-reputation risk). | ✅ code trace | both routes: cap at 200 recipients | **Fixed (code)** |
| **M1** | Seat cap is `count`-then-`insert` with no lock in **both** `attach_member_if_seat_available` and `handle_new_user` → concurrent signups to one org can overflow `seat_limit`. | ✅ logic read | `0016`: `SELECT … FOR UPDATE` on the org row before the count in both paths | **Fixed in 0016** |
| **M2** | `attach_member_if_seat_available`'s "already a member" branch reactivated a **removed** member with no seat check → seat-cap bypass. | ✅ logic read | `0016`: re-check the cap when reactivating a non-active member | **Fixed in 0016** |

### 🟢 LOW

| ID | Gap | Confirmed | Fix | Status |
|---|---|---|---|---|
| **H2** | `purge_org` never cleared `audit_log` (FK `ON DELETE NO ACTION`) → org offboarding would FK-fail **if** audit rows referenced the org. **Downgraded from HIGH:** direct check showed `logAudit` never stamps a tenant `org_id` (rows default to the internal org, which purge refuses), and no superadmin/org route even calls it — so it is **not triggerable today**, only latent/fragile. | ✅ FK fires on a seeded row; ✅ but `logAudit` sets no `org_id` | `0016`: null out `audit_log.org_id` before deleting the org | **Fixed in 0016** |
| **API#4** | `grade` and `dashboard/incident-report` have no in-route auth guard (rely solely on middleware default-deny) — defense-in-depth gap. | ✅ code trace | (deferred — middleware default-deny covers it; add explicit `getAuthedUser()` next) | Open (low) |
| **API#5** | `grade` / `incident-report` didn't wrap `req.json()` → malformed body = 500 not 400. | ✅ code trace | grade route: try/catch → 400 | **Fixed (grade); incident-report open** |
| **API#6** | Several routes return raw Postgres `error.message` to callers (super-admin/org only) — schema leak. | ✅ code trace | (deferred — log server-side, return generic) | Open (low) |
| **API#7** | Member-reactivation PATCH in `org/members` does a non-atomic seat check (TOCTOU), unlike the RPC. | ✅ code trace | (deferred — route through the atomic RPC) | Open (low) |
| **API#8 / L1 / L2 / L3** | Non-constant-time cron secret compare; `supabase_auth_admin` lacks `SELECT organizations` (latent); `current_org`/`current_org_role`/guard lack `search_path`; `resolve_invitation` discloses org name/email for expired tokens. | ✅ | L1 + L2 fixed in `0016`; API#8 & L3 deferred (low) | Partially fixed |

**Verified NOT defects** (checked, no action): tenant isolation on `org/*` (every query pinned to the JWT `orgId`, never a param); JWT claims not spoofable (`getUser()` validates the signed token before reading server-stamped claims); service-role usage appropriate; no anonymous LLM spend on `*/generate*` (all `requireAdmin`); the learner-table RLS (USING + WITH CHECK, fails closed on null org); the profiles privileged-column guard; `invitations`/`audit_log` deny-client; the access-token hook (DEFINER + search_path + grant only to `supabase_auth_admin`).

---

## 3. What changed

**Code (committed, tsc clean):**
- `src/middleware.ts` — `/api/lessons/` added to `EXPENSIVE` (API#1).
- `src/app/api/scenarios/[slug]/grade/route.ts` — anti-harvest answer/debrief gating + JSON guard (API#2, #5).
- `src/components/scenarios/CompletionModal.tsx` — render null answer/explanation gracefully.
- `src/app/api/org/invites/route.ts`, `.../superadmin/orgs/[id]/invites/route.ts` — 200-recipient cap (API#3).

**DB — `supabase/migrations/0016_security_audit_fixes.sql`** (paste-and-run; Claude can't run it):
C1 drop view · H1 RLS+revoke · M3 roster gate · M1/M2 seat lock + reactivation check · H2 purge audit-log · L1 grant · L2 search_path. Idempotent, additive, no data loss.

**Test:** `scripts/test-backend-e2e.mjs` extended to 65 checks (Group G asserts every 0016 fix). Prod-state (0015-deferred + 0016) separately confirmed: view gone, content tables RLS on, anon writes denied (`42501`).

---

## 3a. Correction after running 0016 on production (2026-08-05)

`0016` was executed live on `wrxhxtdllbctsawvewue` ("Success. No rows returned") and verified. Running the verify queries against **real production** surfaced a correction to the audit:

- **C1 and H1 were NOT live in production.** The 0001 speculative schema (`leaderboard` view, `learning_paths`/`modules`/`lessons`/`scenarios`/`badges`) was **never applied to this production database** — `to_regclass` returned NULL for all of them. They existed only in the local full-migration replay (`test-backend-e2e.mjs` applies 0001), which is what surfaced them. So the "live anon cross-tenant leak" framing applied to the *replayed* schema, not to prod. 0016's `to_regclass` guards and `drop view if exists` correctly no-op'd them — no harm, and the repo is now hardened for any environment that *does* have 0001.
- **The genuinely production-relevant fixes are M3, M1, M2, H2, L1, L2 — and those are confirmed live:** the `org_members` read policy now carries the `org_admin`/`instructor`-or-self gate; all six functions were recreated (seat lock, reactivation check, purge audit-log handling, pinned search_path); and `supabase_auth_admin` now has `SELECT` on `organizations`.

Lesson for future audits: replaying all migrations locally can surface objects that were never applied to the live DB. Confirm findings against the real target before assigning production severity.

## 4. Remaining for Tal

1. **Run `0016`** in the Supabase SQL editor (project `wrxhxtdllbctsawvewue`). **C1 is a live anonymous cross-tenant leak — run this first.**
2. Deferred lows (API#4/#6/#7/#8, L3) — non-blocking hardening; can batch later.
3. Unchanged go-live blockers — see [`go-live-blockers-checklist.md`](go-live-blockers-checklist.md) (Supabase Pro backups → then full 0015; Resend domain + `EMAIL_FROM`; `CRON_SECRET`).
