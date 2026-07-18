# HACK THE SOC — Production Readiness & Go-to-Market Plan

*A phased, step-by-step plan to take the platform from a polished client-only prototype to a launched SaaS product, at professional standard. Ordered by dependency: each phase unlocks the next. Effort is rough (S ≤ 2d · M ≤ 1wk · L ≤ 2–4wk · XL > 1mo).*

## Where we are today (honest baseline)
- **Frontend:** Next.js 14 (App Router), strong content + UX, ~28k lines of curriculum, AI-assisted content routes.
- **State:** **`localStorage` only** — XP, progress, streaks, sessions all live in the browser. **No accounts. No server database. No auth. No billing.**
- **Backend:** ~16 API routes, ~10 calling paid LLMs. `.env.example` references **Supabase** (Postgres) — the intended DB, currently **not wired up** (the client libs were removed as unused; a `scripts/seed.ts` + `supabase/migrations` skeleton remains as a reference).
- **Security:** Phase-0 hardening **started this session** — see `SECURITY_PT_REPORT.md`.

**The two true blockers to being a real product are Phase 0 (security) and Phase 1 (identity + a real database).** Everything commercial depends on Phase 1.

---

## Phase 0 — Security hardening & launch blockers  ·  *(started)*
*Goal: safe to expose to the internet at all.*

| # | Step | Status | Effort |
|---|---|---|---|
| 0.1 | HTTP security headers + CSP (Report-Only → enforcing) | ✅ Report-Only shipped | S |
| 0.2 | Rate-limit all `/api/*` (first layer) | ✅ in-memory shipped | S |
| 0.3 | Fix XSS in AI-markdown renderer | ✅ done | S |
| 0.4 | Bump Next 14.2.15 → 14.2.35 (kill critical CVEs) | ✅ done | S |
| 0.5 | **Next 14 → 16 major upgrade** (clear remaining advisories) | ⬜ | M |
| 0.6 | **`zod` validation + body/upload size caps on every route** | ⬜ | M |
| 0.7 | **Durable, authenticated rate limiting** (Upstash Redis / Vercel KV) replacing in-memory | ⬜ | M |
| 0.8 | **Auth gate on every write / LLM / admin route** (depends on Phase 1) | ⬜ | M |
| 0.9 | Error monitoring (Sentry) + structured logging, no secrets in logs | ⬜ | S |
| 0.10 | Secrets: move to host env / secrets manager; **rotate the current keys** (they've been in local dev) | ⬜ | S |
| 0.11 | Per-user + global **AI spend cap / kill-switch** (hard ceiling on provider cost) | ⬜ | S |

**Exit criteria:** `npm audit` clean of prod-runtime criticals/highs; every mutating endpoint authenticated + validated + rate-limited by a durable store; a live PT against staging passes (see 4.9).

---

## Phase 1 — Identity & Data persistence  ·  *the biggest lift*
*Goal: real users, whose progress survives across devices and sessions. This is the foundation for everything commercial.*

1. **Pick the stack** (recommended, all Next-native + Vercel-friendly):
   - **DB:** Postgres via **Supabase** (matches existing `.env.example`; gives auth + storage + RLS) or **Neon** (pure Postgres) + **Drizzle/Prisma** ORM.
   - **Auth:** **Auth.js (NextAuth)** (email + OAuth: Google/GitHub/Microsoft) or **Clerk** (fastest, managed) — Microsoft/Google SSO matters for the B2B SOC-team audience.
2. **Data model** (minimum): `users`, `accounts/sessions`, `organizations`, `memberships(role)`, `user_progress` (rooms, XP, streaks, telemetry), `dashboard_sessions`, `scenario_history`, `certificates`, `ai_usage`.
3. **Migrate state off localStorage → DB** behind a small data-access layer, so every current `localStorage.getItem/setItem` (XP, `room_progress`, `soc_dashboard_sessions`, streak freezes, etc.) reads/writes the server per authenticated user. Keep a localStorage fallback for a signed-out "try it" mode.
4. **One-time import** so an existing signed-out learner can carry their localStorage progress into a new account.
5. **Server-authoritative XP/grades** — move scoring the client currently trusts (XP totals, pass thresholds) server-side to prevent tampering once accounts/leaderboards have value.
6. **RLS / row-ownership** so a user can only read/write their own rows; org admins see their org.

**Effort: XL.** **Exit criteria:** sign up on one device, resume on another; no learner data in localStorage for authed users; admin tooling behind a staff role.

---

## Phase 2 — Multi-tenancy & Monetization
*Goal: someone can pay for it; teams can use it.*

1. **Orgs & roles:** individual learners **and** B2B teams (SOC teams, MSSPs onboarding juniors, bootcamps/universities). Roles: `owner / admin / instructor / learner`.
2. **Billing: Stripe** — subscriptions + **per-seat** for teams; plans e.g. **Free** (limited paths, community scenarios) → **Pro** (full curriculum, certificates, AI grading) → **Team** (seats, admin dashboard, progress reports). Stripe Customer Portal for self-serve.
3. **AI cost governance:** per-plan **AI-usage quotas** metered against the `ai_usage` table; usage visible to the user; overage handling. (Directly caps CRITICAL-1's cost exposure.)
4. **Gating:** feature flags per plan; admin/content-authoring restricted to internal staff.
5. **Instructor/admin dashboard:** team progress, completion, weak-area analytics (the honest Progress data we already compute, aggregated per org).

**Effort: L–XL.** **Exit criteria:** a team can buy N seats, invite learners, see their progress, and be billed monthly.

---

## Phase 3 — Compliance, Legal & Privacy
*Goal: legally allowed to collect user data, especially for EU users.*

1. **Legal pages:** Terms of Service, Privacy Policy, Acceptable Use, Cookie/consent banner (privacy-preserving default).
2. **GDPR** (EU learners are core audience): lawful basis, **DPAs with subprocessors** (Anthropic, OpenAI, host, Stripe), **data export + delete (DSAR) self-serve**, retention policy, records of processing.
3. **Data minimization:** don't send more user data to LLM providers than needed; document what leaves the system.
4. **Security posture page + `security.txt`** + responsible-disclosure policy (fitting for a security product, and a trust signal).
5. **Accessibility statement** (WCAG 2.1 AA — the UX pass already moved toward this).
6. **SOC 2 Type I roadmap** (optional but highly marketable for a SOC-training vendor selling to security teams; start the controls early).

**Effort: M–L (mostly non-eng, needs legal review).** **Exit criteria:** a privacy-conscious EU customer can sign up, understand data use, and export/delete their data.

---

## Phase 4 — Infrastructure, DevOps & Observability
*Goal: it stays up, we can see problems, and we can ship safely.*

1. **Hosting:** **Vercel** (native Next.js) + custom domain + managed TLS; or containerized (Docker) on a cloud host if self-hosting is required.
2. **Environments:** dev / **staging** / prod with isolated secrets and databases.
3. **CI/CD (GitHub Actions):** on every PR run `lint` + `tsc` + `build` + **`npm audit` (fail on high)** + preview deploy; protected `main`.
4. **Dependency hygiene:** Dependabot/Renovate; complete the **Next 16 upgrade** here with full regression.
5. **Observability:** **Sentry** (errors), **PostHog / Plausible** (privacy-friendly product analytics + funnels), uptime monitoring (health check already exists at `/api/health`), log drains.
6. **Edge protection:** **WAF + bot mitigation** (Vercel/Cloudflare) in front of the app; move rate limiting to the durable store from 0.7.
7. **Backups & DR:** automated DB backups, tested restore, documented RPO/RTO.
8. **Performance:** lazy-load heavy libs (`recharts`, `pptxgenjs`, `jspdf`) via `next/dynamic`; image optimization; bundle budget; the big static content files (`scenarios.ts`, room batches) split/loaded on demand.
9. **Live penetration test** against staging (authenticated + unauthenticated) — the black-box PT that this pre-deploy SAST couldn't do. Fix findings before GA.

**Effort: L.** **Exit criteria:** green CI gates every deploy; errors + usage are visible; staging PT passed; backups restore-tested.

---

## Phase 5 — Go-to-Market & Launch
*Goal: the right people find it, try it, and stay.*

1. **Positioning / ICP:** (a) aspiring & junior SOC analysts upskilling; (b) bootcamps & universities; (c) SOC teams / MSSPs onboarding and continuously training juniors. Differentiator: **realistic, vendor-accurate telemetry + no-hints investigation + real incident-report grading** (the depth built this project).
2. **Pricing:** generous **Free** tier to acquire (first paths + a few live scenarios), paid Pro/Team for full curriculum, certificates, AI grading, and team analytics.
3. **Acquisition surface:** marketing landing page (distinct from the app), SEO around "SOC analyst training / blue team practice", a **frictionless demo/sandbox** (the signed-out "try it" mode from Phase 1), and the **downloadable certificate** we already generate as a shareable/credential hook.
4. **Retention engine:** the **fresh-content cadence** (new scenarios weekly) is the core retention lever for a practice platform; plus the streak/XP loops already hardened this session, onboarding, and lifecycle email.
5. **Analytics & funnels:** activation (first room completed), retention (D1/D7/D30), path completion, free→paid conversion — wired via PostHog from Phase 4.
6. **Support & community:** help center / docs, in-app feedback, a Discord/community for learners (network effect + content ideas).
7. **Launch motion:** private **beta → design partners** (a bootcamp or a SOC team) → public launch (Product Hunt, LinkedIn, r/cybersecurity & blue-team communities, relevant newsletters).

**Effort: L (ongoing).** **Exit criteria:** a stranger can discover, try, sign up, pay, and get a measurable first "win" — and you can see each of those steps in analytics.

---

## Critical path (do these in order)
**0.5–0.11 (finish security)** → **Phase 1 (auth + DB)** → **0.8 (auth-gate routes)** → **Phase 2 (billing)** → **Phase 3 (legal, in parallel with 2)** → **Phase 4 (infra + staging PT)** → **Phase 5 (launch)**.

The single highest-leverage next move after this session is **Phase 1** — nothing commercial exists without accounts and a real database. Recommended first concrete step: **stand up Supabase + Auth.js, model `users`/`user_progress`, and migrate the localStorage data layer behind a `useProgress()` hook** so the rest of the app changes in one place.
