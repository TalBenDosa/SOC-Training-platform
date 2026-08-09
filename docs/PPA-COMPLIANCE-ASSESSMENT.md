# PPA / Privacy Protection Law compliance assessment — HACK THE SOC

**Assessed:** 9 August 2026 · **Scope:** the deployed platform as it exists in this repo
**Law:** חוק הגנת הפרטיות התשמ״א-1981 as amended by **תיקון 13** (in force 14 Aug 2025), plus תקנות הגנת הפרטיות (אבטחת מידע) התשע״ז-2017

Every claim below was checked against code, migrations or configuration in this
repository. Where something is a judgement call rather than a verified fact, it
says so. This is an engineering assessment, not legal advice — the cross-border
and contractual items in §5 in particular deserve a lawyer's eye before a
college contract is signed.

---

## 1. What personal data the platform actually holds

Verified against `supabase/migrations/*.sql` and the auth flow.

| Field | Source | Notes |
|---|---|---|
| Email address | signup / invitation | The account identifier |
| Display name | signup | User-chosen |
| Handle (nickname) | signup | Public on the class leaderboard |
| Learning progress | product use | Rooms/scenarios completed, scores, XP, streak |
| Free-text incident reports | product use | Student's own writing, sent to an AI grader |
| Audit trail | privileged actions | Admin/super-admin actions, `public.audit_log` |

**No** national ID (תעודת זהות), phone number, address, payment data, health,
biometric or other special-category data is collected anywhere. Grep for
`teudat|national.?id|id_number` across `src/` and `supabase/` returns only
*lesson content* explaining that DLP tools detect such patterns — never a field.

**Assessment: data minimisation is genuinely strong.** This is the single
biggest factor reducing exposure across everything below, and it should be
treated as a design constraint to defend, not an accident.

---

## 2. Registration and notification duties

Amendment 13 **repealed** the old broad registration duty — the pre-2025 rule
(10,000+ records, or sensitive data, or direct marketing) no longer applies.

| Duty | Trigger | Applies here? |
|---|---|---|
| **Registration** | Data broker (>10k individuals) **or** public body | **No.** The platform does not collect personal data in order to transfer it to others as a business, and is not a public body. |
| **Notification to PPA** | "Especially sensitive information" on **>100,000** individuals | **No.** No especially-sensitive data is held at all, and the population is orders of magnitude below the threshold. |
| **DPO (ממונה על הגנת הפרטיות)** | Public bodies, data brokers, large-scale sensitive-data processors | **No** on current facts. Re-evaluate if scale or data categories change. |

**Assessment: no registration, notification or DPO obligation on today's facts.**
The old "10,000 records" number still circulates widely and does *not* apply —
it survives only in the data-broker context.

---

## 3. Verified controls (evidence, not assertion)

| Requirement | Status | Evidence |
|---|---|---|
| Security measures (תקנות אבטחת מידע 2017) | **Strong** | RLS on all tenant tables; server-side grading; `audit_log` locked to service-role only (migration 0007); all 33 API routes auth-gated; edge middleware default-deny |
| Access control / tenant isolation | **Verified** | Two-college RLS proof runs in CI (`npm run test:tenancy`) |
| Encryption in transit | **Yes** | HSTS `max-age=63072000; includeSubDomains; preload`, plus CSP, X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy |
| Credential hygiene | **Verified** | No secrets in git history; no secret behind a `NEXT_PUBLIC_` prefix; service-role client is `server-only` |
| Access-record retention ≥24 months | **Met** | `audit_log` has no deletion or cleanup path; only `purge_org` clears it, at offboarding |
| Purpose limitation | **Met** | Stated on `/privacy`; no advertising or profiling; no sale of data |
| Sub-processor disclosure | **Met** | Supabase, Vercel and the AI graders are each named on `/privacy` |

---

## 4. Gaps found — and what was done

### 4.1 No privacy notice at the point of collection — **FIXED**

The only link to `/privacy` was in the landing-page footer. A student arriving
from an invite link goes `/join → /signup` and **never sees the landing page**,
so on the invited path — which is the primary path for a college cohort — the
notice reached nobody.

The transparency duty (יידוע נושא המידע) attaches when data is *collected*.
Added a notice directly above the "Create account" button stating what is stored
and why, linking to `/privacy`.

### 4.2 No route to exercise data-subject rights — **FIXED**

`/privacy` said "Contact the platform owner" and gave **no address, form or
channel**. A right with no mechanism is not exercisable, and the law expects a
response within 30 days.

`/privacy` now states the 30-day commitment and gives a real route: the course
administrator (the correct channel in a college deployment, since they already
administer the student's account), plus an optional direct address via the new
`PRIVACY_CONTACT_EMAIL` environment variable. Left unset it falls back to the
administrator route — publishing a wrong or personal address is worse than
routing through the channel that actually works.

> **Action for Tal:** set `PRIVACY_CONTACT_EMAIL` in production to a monitored
> address. This is a one-line config change, not a code change.

### 4.3 Retention was undocumented — **FIXED**

Retention was implemented (audit rows survive until org offboarding) but stated
nowhere. `/privacy` now documents both account-data and 24-month audit-trail
retention.

---

## 5. Previously open items — now closed

All three were closed on 9 August 2026. Each is recorded here with the
resolution, because *how* a judgement call was decided matters more later than
the fact that it was.

### 5.1 No self-service account deletion — **CLOSED**

Was: a student could not delete their own account; deletion existed only as
`purge_org()` (whole-institution, super-admin).

The conflict was real — a student unilaterally deleting their record also
destroys the college's assessment record for a course they may still be taking.
Resolved by splitting on the actual distinction rather than picking one rule for
everyone:

- **Solo learner** (no institution) — deletes immediately, in-product. There is
  no counterparty, so making them wait on a human is friction with no
  justification.
- **Enrolled student** — files a request that their org admin actions, with the
  30-day statutory clock shown in `/manage` and the queue rendered above class
  analytics so a deadline cannot sit below the fold.

The delete itself is a single `auth.admin.deleteUser()` call: every per-user
table already cascades from `auth.users` / `public.profiles`, so the database
removes the whole graph atomically and no hand-maintained purge list exists to
rot. `audit_log.actor_id` is `on delete set null`, so the security record
survives the person — which is what the 24-month retention duty wants.

Built in `supabase/migrations/0027_account_deletion.sql`, `/api/account`,
`/api/org/deletion-requests`, `/account`, and the `/manage` queue.

### 5.2 Cross-border transfer basis — **CLOSED (documented)**

Now recorded in [CROSS-BORDER-DATA-TRANSFER.md](CROSS-BORDER-DATA-TRANSFER.md):
what leaves Israel, to whom, and the basis relied on — necessity for performance
of the contract (s.36), reinforced by the processors' DPAs, with adequacy and
consent explicitly *not* relied on.

The document carries an action register of DPAs still to be filed. Those are
administrative, but they stay ticked-open until the documents actually exist:
having a DPA and being able to produce one are different things, and procurement
asks for the second.

### 5.3 Breach-notification runbook — **CLOSED**

Now at [INCIDENT-RESPONSE-RUNBOOK.md](INCIDENT-RESPONSE-RUNBOOK.md): the
serious/not-serious test decided in advance, a one-hour containment sequence,
the immediate PPA notification path in Hebrew, and — the part easy to miss in a
B2B deployment — notification of **both** the affected colleges (each is the
controller for its own cohort) and the affected students.

One genuine gap remains inside it: the **Deputy incident lead is unassigned**. A
single-person chain has no redundancy, and "immediately" does not pause because
one person is unreachable.

---

## 6. Bottom line

| Area | Verdict |
|---|---|
| Registration / notification / DPO | **Not required** on current facts |
| Data minimisation | **Strong** — the platform's best privacy property |
| Technical security measures | **Strong** and CI-enforced |
| Transparency & consent | **Now compliant** (§4.1) |
| Data-subject rights | **Compliant** — contact route (§4.2) and working deletion (§5.1) |
| Retention | **Documented and met** (§4.3) |
| Cross-border transfer | **Documented** (§5.2) — DPAs still to be filed |
| Breach notification | **Runbook in place** (§5.3) — deputy lead unassigned |

Nothing found rises to a blocking legal exposure at current scale, and every
item this assessment opened has been closed.

Two small things remain, both a signature rather than a sprint:

1. **File the DPAs** listed in the [cross-border register](CROSS-BORDER-DATA-TRANSFER.md#5-action-register).
2. **Name a deputy incident lead** — the notification duty is "immediate", and a
   one-person chain has no redundancy.

And one configuration step: set `PRIVACY_CONTACT_EMAIL` in production (§4.2).
