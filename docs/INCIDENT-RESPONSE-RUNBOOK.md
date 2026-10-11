# Security incident runbook — HACK THE SOC

**Owner:** Tal Ben Dosa · **Last reviewed:** 9 August 2026 · **Review:** every 6 months
**Covers:** a security incident affecting *this platform* and the personal data it holds

Closes §5.3 of [PPA-COMPLIANCE-ASSESSMENT.md](PPA-COMPLIANCE-ASSESSMENT.md).

Amendment 13 requires a **serious security incident** to be reported to the
Privacy Protection Authority **immediately**, and exposes the controller to
statutory damages of up to **NIS 100,000 without proof of harm**. "Immediately"
is not "when we've finished investigating" — which is precisely why the decision
needs to be pre-made rather than improvised at 02:00.

The platform teaches incident response. This is the same discipline turned on
ourselves.

---

## 0. Roles

| Role | Who | Does |
|---|---|---|
| **Incident Lead** | Tal Ben Dosa | Runs the incident, makes the "is it serious" call, is the single decision-maker |
| **Deputy** | *(unassigned — see below)* | Takes over if the Lead is unreachable within 2 hours |

> **Open item:** the Deputy is unassigned. A single-person chain has no
> redundancy — if the Lead is on a flight, the "immediate" clock runs anyway.
> Name someone, even informally.

---

## 1. Severity — decide this first

Decide in **one hour**, on the information available. Do not wait for certainty:
the standard is a reasonable belief, not a proven fact.

### SERIOUS — notify the PPA immediately

Any of:

- Unauthorised access to, or exfiltration of, the accounts/progress database
- Compromise of the **service-role key**, database credentials, or a Supabase admin session
- A vulnerability that let one tenant read another tenant's data (RLS bypass, cross-tenant IDOR)
- Account takeover affecting multiple users, or any admin/super-admin account
- Ransomware, destruction, or unauthorised alteration of personal data
- Confirmed public exposure of personal data (a leaked backup, a public bucket, an indexed endpoint)

### NOT SERIOUS — record, fix, no PPA notification

- A vulnerability found by review or scanning with **no evidence of exploitation**
- A dependency advisory in code that is not reachable (see `scripts/audit-gate.mjs`)
- A single user's own credential phished, contained on their account, with no platform weakness
- Availability-only events (an outage) with no confidentiality or integrity impact

**If it sits on the line, treat it as SERIOUS.** Over-notifying costs
paperwork; under-notifying is the thing with a NIS 100,000 tail.

---

## 2. First hour

1. **Contain before you tidy.** Rotate what is exposed:
   - `SUPABASE_SERVICE_ROLE_KEY`, then redeploy
   - Supabase database password, and revoke active sessions
   - `CRON_SECRET`, `RESEND_API_KEY`, AI provider keys, as applicable
2. **Preserve evidence.** Do **not** clear `public.audit_log`. Snapshot the
   database before remediation. Export Vercel and Supabase logs — they age out.
3. **Start a timeline** — one file, append-only, every timestamp in UTC:
   when detected, by whom, what was seen, every action taken and when. This
   becomes the PPA record and the reconstruction later.
4. **Do not discuss externally** before §3 and §4. No partial statements.

---

## 3. Notify the PPA (SERIOUS only) — immediately

**Do not wait for the investigation to finish.** File on what is known, and
supplement later.

- Channel: the Privacy Protection Authority's reporting route (rashut-hagana@justice.gov.il / the current PPA online form — **verify the channel is still current at review time**).
- Language: Hebrew.
- Include: what happened, when, what data categories and roughly how many people, what has been done to contain it, and what comes next.
- Then keep the PPA updated as the picture firms up.

---

## 4. Notify the people affected

Amendment 13 may require notifying data subjects as directed by the PPA — and
for a B2B deployment there are **two** audiences, which is easy to get wrong:

1. **The colleges** (each institution is the controller for its own cohort).
   Notify the org admin of every affected organisation directly. They have their
   own obligations toward their students and cannot meet them if they hear late.
2. **The students** whose data was affected — **in Hebrew** for Israeli residents.

Say plainly: what happened, what data of theirs was involved, what has been done,
what they should do (change password; be alert to phishing referencing the
platform), and how to reach us.

No minimising language, no "out of an abundance of caution" filler.

---

## 5. After

- Fix the root cause. If it is code, add the regression test or gate that would
  have caught it — the same standard the content and audit gates already hold.
- Record the incident, decisions and timings in this repo's docs.
- Re-run the assessment in [PPA-COMPLIANCE-ASSESSMENT.md](PPA-COMPLIANCE-ASSESSMENT.md) if the incident changed what data is held or who processes it.
- Update this runbook with whatever it got wrong. A runbook that survives an
  incident unchanged was probably not consulted.

---

## 6. Standing prevention (already in place)

Not aspirational — each of these exists in the repo today:

- RLS on tenant tables, with a two-college isolation proof in CI (`npm run test:tenancy`)
- Default-deny edge middleware on `/api/*`; all API routes auth-gated
- Service-role client is `server-only` and never reaches the browser bundle
- `public.audit_log` writable only by the service role (migration 0007), retained ≥24 months
- Dependency gate failing on any unreviewed production advisory (`npm run audit:deps`)
- Security headers incl. CSP, HSTS preload, frame-deny

**Quarterly check:** confirm the audit-gate allowlist is still justified, that
CI is green, and that the secrets above have a known rotation path.
