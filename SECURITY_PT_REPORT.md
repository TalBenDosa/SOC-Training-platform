# HACK THE SOC — Application Security Assessment & PT Report

**Date:** 2026-07-18 · **Assessor:** Engineering/Security lead · **Scope:** full source tree of the Next.js app (pre-deployment).

## Method & honest scope note

A classic penetration test runs against a **deployed, live target** with authorization to attack that host. This platform is **not yet deployed** and there was no live target, so what was performed here is the correct assessment for this stage: a **code-level application-security review (SAST) + dependency audit** of the whole repository, plus live verification of the fixes against the local dev server. This is exactly the "PT before launch" that gates a first deploy — a live black-box/authenticated PT against staging is scheduled as a Phase-4 item in `PRODUCTION_READINESS_PLAN.md` once auth + infra exist.

The app today is **client-only**: no user accounts, no server-side database, all state in `localStorage`. That shrinks the classic attack surface (no auth to bypass, no SQL, no server-stored PII to steal *yet*) but concentrates risk in the **~16 API routes**, ~10 of which call **paid LLM providers** (Anthropic / OpenAI).

---

## Findings — severity, damage potential, status

### 🔴 CRITICAL-1 · Unauthenticated + unthrottled paid-LLM endpoints → financial DoS + prompt-injection abuse
**Where:** `/api/scenarios/generate`, `/api/quizzes/generate`, `/api/lessons/generate`, `/api/lessons/generate-stream`, `/api/lessons/import-pptx`, `/api/lessons/validate`, `/api/lessons/export-pptx`, `/api/dashboard/ai-grade`, `/api/dashboard/incident-report`, `/api/scenarios/[slug]/grade`, `/api/admin/validate-logs`.
**What could have happened:** on a public URL, anyone could script these endpoints in a loop. Each call spends real money on Anthropic/OpenAI. **Damage: an attacker (or a runaway client bug) could burn the entire API budget in minutes — potentially thousands of dollars overnight — and trigger provider account suspension**, taking the whole product offline. Secondarily, the free-text inputs (`topic`, report text, uploaded PPTX) flow into LLM prompts, so a crafted payload could attempt **prompt injection** to manipulate generated content or extract the system prompt — all billed to the owner.
**Fixed (first layer):** added `src/middleware.ts` — per-IP fixed-window rate limiting on all `/api/*` (expensive routes **10 req/min**, general **100 req/min**, `429 + Retry-After` on breach). **Verified live:** requests 1–10 → `200`, request 11+ → `429`.
**Residual (in plan):** the limiter is in-memory (per-instance) so it resets on cold start and can be spread across instances → **needs a durable store (Upstash Redis / Vercel KV) keyed by IP *and* authenticated user id**, plus **real auth on every write/LLM/admin route**. Phase 0/1.

### 🔴 CRITICAL-2 · Next.js 14.2.15 vulnerable to a large CVE set, incl. Middleware Authorization Bypass
**What:** the pinned `next@14.2.15` was affected by ~20 advisories — SSRF via middleware redirects, multiple DoS via Server Components/Image Optimizer, cache poisoning, and notably **Authorization Bypass in Next.js Middleware (GHSA-f82v-jwr5-mffw / CVE-2025-29927)** — which is directly relevant because our new rate-limit/auth lives in middleware and could be bypassed via a crafted `x-middleware-subrequest` header.
**Damage potential:** middleware-based controls silently bypassed; denial of service; SSRF from the server's network position.
**Fixed:** bumped to **`next@14.2.35`** (latest 14.x patch, non-breaking) — this **eliminated the CRITICAL advisory** and the middleware-bypass class. Dependency count dropped from *1 critical / …* to **0 critical**.
**Residual (in plan):** a handful of newer advisories are only patched in **Next 16** — a **major upgrade** deliberately **not** auto-applied (14→16 needs a real migration + full regression). Tracked as the #1 Phase-0 hardening task.

### 🟠 HIGH-1 · Stored/Reflected XSS in the AI-generated markdown renderer
**Where:** `src/app/(app)/learn/[slug]/[lesson]/page.tsx` → `MarkdownBlock` ran a regex markdown→HTML transform and injected the result via `dangerouslySetInnerHTML` **with no sanitization**. The `body` is **AI-generated** and influenced by user-supplied generation prompts → untrusted.
**Damage potential:** a lesson body containing `<img src=x onerror="…">` or `<script>` would execute in the victim's browser → **steal `localStorage` (XP/progress today; session tokens once auth exists), deface the page, or pivot**. Classic stored-XSS blast radius once content is shared between users.
**Fixed:** the renderer now **HTML-escapes `&` and `<` *before* any markdown replacement**, so injected tags become inert text while the whitelisted formatting tags we emit still render. **Verified:** tsc clean; the escape-before-format invariant neutralizes tag injection by construction.

### 🟡 MEDIUM-1 · Missing HTTP security headers (clickjacking, MIME sniffing, referrer leakage)
**What:** no CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, or HSTS; framework version leaked via `X-Powered-By`.
**Damage potential:** the app could be framed by a hostile site for **clickjacking/UI-redress**; MIME-sniffing and referrer leakage; version fingerprinting.
**Fixed:** `next.config.mjs` now sets `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` (camera/mic/geo/FLoC off), `Strict-Transport-Security` (2y + preload), `X-DNS-Prefetch-Control: off`, and a **CSP in Report-Only mode** (safe rollout — reports violations without breaking the app). `poweredByHeader:false`. **Verified live via curl** — all headers present, `X-Powered-By` gone.
**Residual (in plan):** promote CSP from Report-Only to **enforcing with per-request nonces** after collecting reports. Phase 4.

### 🟡 MEDIUM-2 · No authentication / authorization anywhere
**What:** a single hardcoded user; the content-authoring **Admin** panel and its API are open; no accounts, sessions, or roles.
**Damage potential:** pre-launch this is a **hard blocker** rather than an exploit (there's nothing per-user to steal) — but the moment the app is public, the admin/content tooling is world-accessible and there's no way to attribute or protect user data. Blocks any multi-user/SaaS use.
**Status:** **not a code auto-fix** — it's a foundational build. Phase 1 (Identity & Data).

### 🟡 MEDIUM-3 · Unbounded / unvalidated API inputs
**What:** several routes `await req.json()` with no schema/size validation; `/api/lessons/import-pptx` accepts file uploads. `zod` is already a dependency but not consistently applied at the boundary.
**Damage potential:** oversized-payload DoS, memory exhaustion, malformed-input crashes.
**Fixed (partial):** the rate-limiter caps volume. **Residual:** add `zod` validation + explicit body/upload size caps on every route. Phase 0.

### ⚪ LOW · Dev-only dependency advisories
`esbuild` (arbitrary file read via the **dev** server on Windows) and `glob` CLI command injection are **dev-dependencies with no production-runtime exposure**; `postcss` moderate is nested under Next and clears with the Next 16 upgrade. Patched what was non-breaking via `npm audit fix`; the rest ride the planned Next 16 upgrade.

---

## What was auto-fixed this session (summary)

| # | Finding | Severity | Action | Verified |
|---|---|---|---|---|
| CRIT-1 | Unthrottled paid-LLM endpoints | Critical | Added edge rate-limit middleware (10/min expensive · 100/min general) | ✅ live: 11th req → 429 |
| CRIT-2 | Next.js CVE swarm + middleware auth-bypass | Critical | Bumped `next` 14.2.15 → 14.2.35 (0 critical remaining) | ✅ audit + tsc + app loads |
| HIGH-1 | XSS in AI-markdown renderer | High | Escape `&`/`<` before markdown transform | ✅ tsc + by construction |
| MED-1 | Missing security headers | Medium | Full header set + CSP Report-Only + no `X-Powered-By` | ✅ live via curl |
| LOW | `ws` etc. transitive vulns | Low/High | `npm audit fix` (non-breaking) | ✅ re-audit |

**Verification:** `npx tsc --noEmit` → 0 errors; dashboard loads with 0 console errors; headers and 429 throttling confirmed against the running server.

## Top residual risks → owned by the production plan
1. **Durable, authenticated rate limiting** (replace in-memory) + **auth on all write/LLM/admin routes** — Phase 0/1.
2. **Next 16 major upgrade** to clear remaining advisories — Phase 0.
3. **Authentication + per-user data in a real DB** (currently none) — Phase 1.
4. **`zod` validation + size caps** on every endpoint — Phase 0.
5. **Enforcing CSP with nonces**, secrets manager + key rotation, live staging PT, dependency scanning in CI — Phase 4.

*No secrets are committed to git (`.env*` is git-ignored; only `.env.example` is tracked). Verified.*
