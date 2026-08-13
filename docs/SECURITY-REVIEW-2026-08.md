# Security Review & Pre-Production Penetration Test — HACK THE SOC

**Date:** 2026-08-13
**Scope:** Local source of this repository (owner-authorized). Production Supabase, the GitHub remote, and the live domain were treated as **OUT OF SCOPE** — no active testing was performed against them.
**Method:** Static code review + data-flow tracing across all 45 API routes, the RLS/migration layer (0001–0033), the auth guards, the middleware, and the frontend. No destructive actions, no DoS, no changes to code. Every finding below was verified by reading the code first-hand; four parallel review agents provided breadth and each of their material claims was independently re-checked against the source.

---

## Executive summary

This is a **well-hardened codebase** with a clear history of pentest-driven fixes. The authorization model is sound and fail-closed; multi-tenant **read** isolation is enforced at the database (RLS) independent of app-layer bugs; there is **no committed secret**, the service-role key is server-only, and Next.js is patched against the middleware-auth-bypass CVE-2025-29927.

No **Critical** or **High** issue was found. The findings cluster into two themes:

1. **Assessment integrity** — a student can read scenario answers and forge graded history / XP. Individually Medium/Low; **chained**, they let a learner fabricate a flawless record without doing any work, which undermines the platform's core B2B value proposition (colleges buy it *for* trustworthy assessment).
2. **Hardening** — a spoofable rate-limit key, a permissive CSP, and a handful of Low write-side / info-disclosure items.

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 4 |
| Low | 5 |
| Informational | 4 |

---

## 1. Attack Surface Map (representative — full inventory was built for all 45 routes)

`METHOD | PATH | AUTH | ROLE | SENSITIVE DATA | RISK CLASS → verdict`

**Unauthenticated (throttle = middleware per-IP only):**
- `GET | /api/health | none | — | uptime/version | info → clean`
- `GET | /api/reputation/hash | none | — | mock verdict | abuse → clean (local mock, no SSRF)`
- `GET | /api/scenarios | none | — | slug/title | enum → clean (no answers)`
- `GET | /api/leaderboard | none→getUser | user | display_name/xp | tenant → clean (definer scoped to caller org)`
- `GET | /api/invitations/[token] | none | — | org/role/email | enum → clean (token = secret, high entropy)`
- `GET | /api/access-codes/[code] | none | — | {valid,orgName} | enum → clean`

**Authenticated (getAuthedUser — soft):**
- `GET | /api/scenarios/[slug] | user | user | scenario bundle | **BOLA/answer-key → M1 (leaks verdict+IOCs)**`
- `POST | /api/scenarios/[slug]/grade | user | user | — | integrity → clean (server-authoritative)`
- `POST | /api/dashboard/incident-report | user | user | — | prompt-injection → clean (deterministic score, fenced input)`
- `GET | /api/lessons/[slug] | user | user | AI content | cost → clean (budget-gated)`
- `POST | /api/rooms/[id]/tasks/[taskId]/submit | user(guest ok) | — | grade | mass-assign → clean`
- `* | /api/account/* | user | self | own account | self-scope → clean`
- `POST/GET/PATCH | /api/feedback | user/admin | — | reports | IDOR → clean`

**Org-admin (requireOrgAdmin — orgId from JWT):**
- `* | /api/org/members, /org/students/[id], /org/analytics, /org/assignments, /org/class-code, /org/invites, /org/deletion-requests, /org/branding` → **all clean** — every query pinned to `user.orgId`, several with explicit `.eq("org_id")` re-assertions and anti-IDOR guards.

**Super-admin (requireSuperAdmin — cross-tenant by design):**
- `* | /api/superadmin/*` → clean — trusting `[id]` is correct here (cross-org is the function); PATCH fields strictly whitelisted (no mass assignment); internal org protected.

**Admin (requireAdmin):**
- `* | /api/admin/*, /api/lessons/generate*, /import-pptx, /export-pptx, /validate, /quizzes/generate, /scenarios/generate` → clean — fixed table whitelist, no SSRF (PPTX parsed client-side), status clamped.

**Cron (CRON_SECRET, fail-closed):**
- `/api/cron/expire-orgs, /api/cron/nudge-lapsed` → clean (L4 = non-constant-time compare).

---

## 2. Findings

### M1 — `GET /api/scenarios/[slug]` leaks the verdict, scored IOCs, and kill-chain

- **Severity:** Medium · **CVSS:3.1** ~5.0 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N)
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-200 (Exposure of Sensitive Information)
- **OWASP:** API1:2023 (BOLA) / API3 (Broken Object Property Level Authorization)
- **Component / File:** `src/app/api/scenarios/[slug]/route.ts:43-46`
- **Description:** The route sanitizes the scenario bundle by destructuring out only `narrative` and `learning_objectives`, then returns `...rest`. `rest` still contains `attack_kind`, `iocs`, and `killchain` (present in every bundle — e.g. `src/lib/sim/scenarios.ts:1071-1085`). The route's own header comment claims "The answer key and debrief are stripped server-side, so they cannot leak" — this is true only for the per-question `answer`/`explanation`, not for these three fields.
- **Attack scenario:** A signed-in student calls `GET /api/scenarios/ransomware-lockbit` with their session cookie and receives `attack_kind`. The grader derives the verdict from exactly that value: `expectedVerdict = bundle.attack_kind === "false_positive" ? "benign" : "malicious"` (`grade/route.ts:116`). The response also lists `iocs`, whose `.value`s are the exact strings the grader matches to award the evidence rubric (`grade/route.ts:126,158`). The student submits the correct verdict citing the exact indicators and maxes the graded incident report without investigating a single log.
- **Impact:** Defeats the assessment integrity of the scenario exercises — the graded, certificate-bearing part of a platform sold to colleges. No cross-user/tenant data exposure.
- **Remediation:** Strip verdict/evidence/debrief fields from the public shape (whitelist rather than blacklist).
- **Secure code:**
  ```ts
  const { attack_kind, iocs, killchain, narrative, learning_objectives, threat_actor, ...safe } = bundle;
  return NextResponse.json({
    ...safe,
    questions: (bundle.questions ?? []).map(({ id, prompt, kind, options, xp }) => ({ id, prompt, kind, options, xp })),
  });
  ```
  Prefer an explicit allowlist of the fields the investigator legitimately needs (alerts, events, difficulty, title, questions-without-answers).
- **Verification:** `GET /api/scenarios/<slug>` as a student → response must not contain `attack_kind`, `iocs`, or `killchain`. Add a test asserting these keys are absent.

### M2 — Rate-limit bypass via `X-Forwarded-For` spoofing

- **Severity:** Medium · **CVSS:3.1** ~5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)
- **CWE:** CWE-290 (Authentication/Authorization Bypass by Spoofing) / CWE-770 (Allocation Without Limits)
- **OWASP:** API4:2023 (Unrestricted Resource Consumption)
- **Component / File:** `src/middleware.ts:48-52`
- **Description:** `clientIp()` returns `req.headers.get("x-forwarded-for").split(",")[0]` — the **left-most** XFF entry. On a proxied platform (Vercel) the trusted client IP is the platform-set `x-real-ip` (and the right-most XFF hop); the left-most entries are **client-supplied** and spoofable. The rate limiter keys on this value, so an attacker rotates `X-Forwarded-For` per request to land in a fresh bucket every time.
- **Attack scenario:** An attacker scripts requests to the unauthenticated routes (`/api/reputation/hash`, `/api/scenarios`, `/api/access-codes/[code]`, `/api/invitations/[token]`), sending `X-Forwarded-For: <random>` on each. The per-IP limiter (the *only* throttle on those routes) never trips → unbounded enumeration / resource use. For the authenticated paid-LLM routes the impact is capped by the second-layer per-org budget, so the effect there is partial.
- **Impact:** Financial-DoS / enumeration surface on the endpoints the limiter exists to protect.
- **Remediation:** Derive the client IP from the platform-trusted source, not the left-most XFF hop.
- **Secure code:**
  ```ts
  function clientIp(req: NextRequest): string {
    // Vercel sets x-real-ip to the true edge-observed client IP (not client-spoofable
    // through the proxy). Fall back to the RIGHT-most XFF hop, then unknown.
    const real = req.headers.get("x-real-ip");
    if (real) return real.trim();
    const fwd = req.headers.get("x-forwarded-for");
    if (fwd) { const p = fwd.split(","); return p[p.length - 1].trim(); }
    return "unknown";
  }
  ```
  (Or use `ipAddress(req)` from `@vercel/functions`.)
- **Verification:** Two requests with different `X-Forwarded-For` but same real client must share a bucket (second is throttled once the limit is hit).

### M3 — `profiles.xp_offset` is client-writable → unbounded XP / rank forgery

- **Severity:** Medium · **CVSS:3.1** ~4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N)
- **CWE:** CWE-639 / CWE-284 (Improper Access Control)
- **OWASP:** API3:2023 (Broken Object Property Level Authorization) / API6 (business flow abuse)
- **Component / File:** `supabase/migrations/0008_server_authoritative_xp.sql:105` + `0016_security_audit_fixes.sql:266-269` + `0011:52-53`
- **Description:** XP is meant to be server-authoritative: `revoke update (xp, level)` (0008:105) blocks clients from writing `xp`/`level`, and `recompute_user_xp()` sets `xp = greatest(0, xp_offset + Σ xp_earned)`. But **`xp_offset` is neither column-revoked nor restored by the privilege-guard trigger** (0016 restores only `id/role/org_id/is_platform_admin`), and the "profiles self update" RLS policy lets a user UPDATE their own row. `0025` bounds per-row `xp_earned` (≤1000) but never bounds `xp_offset`, and `recompute` has no upper cap.
- **Attack scenario:** A signed-in user, via the browser anon client, runs `update profiles set xp_offset = 9999999 where id = auth.uid()` (permitted — only `xp`/`level` are revoked, and the guard trigger ignores `xp_offset`), then triggers a recompute by writing any own `room_progress` row. `xp` becomes `9999999 + records` — top of the leaderboard, arbitrary rank, bypassing the explicit 0025 mitigation.
- **Impact:** Leaderboard / rank / XP integrity (the org-scoped class leaderboard is a sold feature). Integrity-only; no data exposure.
- **Remediation:** Add `xp_offset` (and the other cosmetic columns — see L-INFO) to the column revoke and the guard-trigger restore list.
- **Secure code (migration):**
  ```sql
  revoke update (xp_offset, rank, streak_days) on public.profiles from anon, authenticated;
  -- and in guard_profile_privileged_columns():
  new.xp_offset := old.xp_offset;
  ```
- **Verification:** As a non-admin, `update profiles set xp_offset = 1e6 where id = auth.uid()` must be a no-op / denied; `xp` unchanged after a completion insert.

### M4 — CSP `script-src` allows `'unsafe-inline'` and `'unsafe-eval'`

- **Severity:** Medium (hardening) · **CWE:** CWE-1021 / CWE-693 (Protection Mechanism Failure)
- **OWASP:** API8:2023 / A05 (Security Misconfiguration)
- **Component / File:** `next.config.mjs:23`
- **Description:** `script-src 'self' 'unsafe-inline' 'unsafe-eval'`. Both keywords defeat most of CSP's value as an XSS backstop: an injected inline `<script>` still runs and `eval` is permitted. The code documents this as the known final CSP step (a nonce migration).
- **Attack scenario:** If any future XSS sink is introduced (e.g. a new component rendering unescaped content), CSP would not contain it. Today the app neutralizes XSS at the source (verified: the AI-markdown sanitizer and Mermaid `securityLevel:"strict"` are correct), so this is latent, not directly exploitable.
- **Impact:** Reduced defense-in-depth; a single future XSS becomes fully exploitable.
- **Remediation:** Emit a per-request nonce from middleware and use `script-src 'self' 'nonce-<rand>' 'strict-dynamic'`; drop both `unsafe-*`. Also tighten `connect-src`/`img-src` from `https:` toward an allowlist (Supabase origin, self, data:).
- **Verification:** Response CSP header contains a nonce and no `unsafe-inline`/`unsafe-eval`; app still renders (no console CSP violations).

---

### Low findings

**L1 — Unnecessary client INSERT grants leave `org_id`/`correct` unpinned (integrity forgery + limited cross-tenant injection)**
`content_feedback` (`0022:59-60,83`) and `task_attempts` (`0031:37-38,57`) grant INSERT to `authenticated` with `WITH CHECK (user_id = auth.uid())` only — `org_id` (and `task_attempts.correct`) are unconstrained; `account_deletion_requests` (`0027:81-83`) likewise. All three tables' real writes go through the **service role** (feedback route, submit route, account route), so these client grants are dead surface. A student can `insert into task_attempts (user_id, org_id, correct, …) values (auth.uid(), current_org(), true, …)` to fabricate a perfect graded history the instructor console reads, or inject an attacker-controlled `content_feedback.message` stamped with another org's `org_id` (a phishing string in that college's triage inbox — gated by needing the victim org's UUID, which RLS doesn't expose). **Fix:** `revoke insert on {content_feedback, task_attempts, account_deletion_requests} from authenticated;` (rely on the service-role routes), or pin `org_id = public.current_org()` in each `WITH CHECK`. CWE-639/CWE-284, OWASP API3.

**L2 — Verbose DB error returned to a student-reachable route**
`src/app/api/account/renew-affiliation/route.ts:42` returns raw Postgres `error.message` to the caller on an unmapped RPC exception (schema/driver disclosure). Many staff-only routes do the same (lower concern). **Fix:** log server-side, return a generic message. CWE-209, OWASP API8.

**L3 — `?next=` open-redirect edge (backslash)**
`src/app/(auth)/login/page.tsx:25` rejects `//` but not `/\evil.com`, which browsers normalize to protocol-relative. Mitigated by consumption via `router.push` (client router, not `window.location`), so a true external redirect is unlikely. **Fix:** `const nextPath = /^\/(?![/\\])/.test(rawNext) ? rawNext : "/welcome";`. CWE-601.

**L4 — Cron secret compared non-constant-time**
`cron/expire-orgs/route.ts:28`, `nudge-lapsed/route.ts:93`: `auth === \`Bearer ${secret}\``. Timing side-channel in principle; negligible against a high-entropy secret over the network. **Fix:** `crypto.timingSafeEqual` on equal-length buffers. CWE-208.

**L5 — Rate-limit fallback is per-instance in-memory + broad CSP fetch origins**
Without `UPSTASH_REDIS_*`, the limiter is a per-serverless-instance counter (`rateLimit.ts`), so the effective limit multiplies by the instance count. Documented; Upstash is the production posture. Ensure Upstash env is set in prod. (Also the `connect-src/img-src 'https:'` breadth from M4.) CWE-770.

---

### Informational / defense-in-depth

- **I1 — Stale JWT role window:** the older org-staff RLS policies (`0011:57-61`, `0011:86-90`) gate on the JWT `org_role` claim, so a demoted instructor keeps roster read until token refresh (~1h). Newer policies (0027/0028/0031) correctly check `org_members` directly — back-port that pattern.
- **I2 — No `FORCE ROW LEVEL SECURITY`:** not a client vector (anon/authenticated aren't table owners), but worth adding on tenant tables for belt-and-suspenders.
- **I3 — `profiles.rank`/`streak_days` self-writable:** same class as M3, cosmetic only — fold into the M3 revoke.
- **I4 — `override` pins in `package.json`** (postcss/sharp/dompurify) are correct but silently persist after upstreams fix — re-verify on each dependency bump.

---

## 3. Attack chains (low/medium individually → high combined)

**Chain A — "Perfect student" (assessment-integrity break).**
`M1` (read `attack_kind` + scored `iocs` for every scenario) → submit flawless graded incident reports → `L1` (forge `task_attempts.correct = true` history the instructor dashboard shows) → `M3` (inflate `xp_offset` to top the class leaderboard). A learner produces a spotless, certificate-worthy record and #1 rank **without completing any exercise**. For a product whose B2B pitch is *trustworthy* competency assessment for colleges, this chain is the highest-business-impact issue in the report even though each link is Medium/Low. **Priority to break the chain: M1 first (it's the enabler), then L1, then M3.**

**Chain B — Cost/enumeration.**
`M2` (XFF spoof) removes the per-IP cap on the unauthenticated endpoints → unlimited enumeration of access-codes / invitations / scenarios and free hammering of the mock reputation endpoint. The paid-LLM routes remain capped by the per-org budget, so this is contained to abuse/enumeration rather than unbounded spend.

---

## 4. Priority table

| Priority | Finding | Severity | Component | Exploitability | Fix |
|---|---|---|---|---|---|
| **P1** | M1 scenario verdict/IOC leak | Medium | scenarios/[slug]:43 | Easy (curl w/ session) | Allowlist safe fields |
| **P1** | M2 XFF rate-limit bypass | Medium | middleware.ts:48 | Easy (header rotate) | Use x-real-ip / rightmost hop |
| **P2** | M3 xp_offset forgery | Medium | 0008/0016 SQL | Easy (own-row update) | Revoke + guard xp_offset |
| **P2** | M4 CSP unsafe-inline/eval | Medium | next.config.mjs:23 | Latent (needs future XSS) | Nonce + strict-dynamic |
| **P2** | L1 unpinned client INSERT | Low | 0022/0031/0027 | Moderate (SQL via anon) | Revoke client INSERT |
| **P3** | L2 verbose DB error | Low | renew-affiliation:42 | Passive | Generic message |
| **P3** | L3 backslash open-redirect | Low | login:25 | Hard (router.push) | Reject `\` |
| **P3** | L4 cron non-constant compare | Low | cron/*:28 | Negligible | timingSafeEqual |
| **P3** | L5 in-mem limiter / broad CSP origins | Low/Info | rateLimit.ts / config | Config | Set Upstash env; tighten origins |
| **P3** | I1 stale-role window | Info | 0011 | ~1h window | Check org_members in policy |

**There is no P0.** Nothing here blocks production on a Critical/High basis; P1 items should be fixed before the next college onboards because they touch assessment integrity, which is the product's selling point.

---

## 5. What was checked and is genuinely solid

- **Auth guards** (`apiGuard.ts`): fail-closed, JWT validated via `getUser()` (not `getSession()`); org claims decoded unsigned but only after `getUser()` validates the same token — invariant holds in every server path.
- **RLS**: per-user + per-org isolation with matching `WITH CHECK`; the `guard_profile_privileged_columns` trigger freezes `role/org_id/is_platform_admin` (blocks self-escalation to platform admin); `organizations`/`org_members`/`invitations`/`audit_log` locked; `org_leaderboard` definer function scoped by `current_org()` (C1 leak genuinely closed); **every** SECURITY DEFINER function sets `search_path`; the access-token hook is `revoke execute from authenticated, anon` and stamps only server-derived claims.
- **No mass assignment** anywhere — writes take identity from the JWT, not the body; super-admin PATCH strictly whitelists fields.
- **Secrets**: none committed; service-role key `import "server-only"`, never `NEXT_PUBLIC_`.
- **Dependencies**: Next.js 15.5.21 — **patched** against CVE-2025-29927; no `xlsx`/sheetjs; sane `override` pins.
- **XSS**: AI-markdown sanitizer escapes `&`/`<` before any tag emission and uses only hardcoded attributes (no breakout); Mermaid strict; SVG figures via `<img src>` (inert). Verified first-hand.
- **SSRF**: `import-pptx` parses client-side; no server-side fetch of user URLs.
- **CORS**: none set (no wildcard, no Origin reflection).

---

## 6. Remediation status (applied 2026-08-13, owner-approved)

| # | Finding | Status |
|---|---------|--------|
| M1 | scenario verdict/IOC/killchain leak | **Fixed** — allowlist in `scenarios/[slug]/route.ts` (default-deny; a future bundle field can't leak) |
| M2 | XFF rate-limit bypass | **Fixed** — `clientIp()` uses platform-trusted `x-real-ip` / rightmost hop |
| M3 | `xp_offset` XP forgery | **Fixed in production** — migration 0034 freezes `xp_offset` in the guard trigger (verified: guard body + privilege checks, committed transactionally) |
| L1 | unpinned client INSERT (3 tables) | **Fixed in production** — migration 0034 revokes client INSERT; reads + service-role writes verified intact |
| L2 | verbose DB error (student route) | **Fixed** — generic message + server-side log |
| L3 | backslash open-redirect | **Fixed** — `^/(?![/\\])` guard |
| L4 | cron non-constant-time compare | **Fixed** — `constantTimeEquals` helper on both cron routes |
| M4 | CSP `unsafe-inline`/`unsafe-eval` | **Partially fixed** — `connect-src`/`img-src` tightened to a Supabase allowlist (browser-verified). The `script-src` nonce migration is **HELD**: it requires nonce injection through the auth-critical middleware and behaves differently in dev vs prod, so it needs a dedicated staging smoke-test before shipping — not a blind prod change. |
| L5 | in-memory rate-limit fallback | **Operational** — ensure `UPSTASH_REDIS_REST_URL/TOKEN` are set in production; no code change. |
| I1–I4 | stale-role window, no FORCE RLS, rank/streak self-writable, override pins | **Accepted residuals** — documented, Low/Info. `rank` remains cosmetically forgeable (self-corrects on the next XP recompute); not worth the guard-trigger ordering risk. |

**A note on method.** The M3 column-level `REVOKE UPDATE(col)` in the first migration draft was caught as *ineffective* by the transactional verifier before commit (Postgres does not let a column REVOKE subtract from a table-level grant), and rolled back. The working control is the guard trigger, which reverts the column for every user-driven update regardless of grants — the same mechanism that already blocks `is_platform_admin` self-escalation. This is exactly why the migration ran inside a transaction with post-apply privilege assertions.

*Code changes are committed to the repository; migration 0034 is applied to the production database. M4's script-src nonce is the one deliberately-deferred item.*
