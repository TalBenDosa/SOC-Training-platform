# Cross-border data transfer — basis and safeguards

**Owner:** Tal Ben Dosa · **Last reviewed:** 9 August 2026 · **Review:** annually, or on any change of processor
**Applies to:** HACK THE SOC (hack-the-soc), personal data of Israeli residents

Closes §5.2 of [PPA-COMPLIANCE-ASSESSMENT.md](PPA-COMPLIANCE-ASSESSMENT.md). Its
purpose is to be the document a college's procurement or legal reviewer asks
for. It records what leaves Israel, why that is lawful, and what safeguards
apply — decisions that were already effectively made, but written nowhere.

> This is an internal record, not legal advice. Have counsel confirm §4 before
> signing an institutional contract.

---

## 1. What personal data exists

Email address, display name, handle, learning progress (rooms/scenarios
completed, scores, XP, streak), free-text incident reports written by the
student, and an audit trail of privileged actions.

**No** national ID, phone number, address, payment data, health, biometric or
other special-category data is collected. The attack data students investigate
is entirely synthetic and contains no real personal information.

This matters legally: the transfer analysis below concerns ordinary contact and
progress data, not sensitive data, which is what keeps the risk profile modest.

---

## 2. Where it goes

| Processor | Role | Data it sees | Location |
|---|---|---|---|
| **Supabase** | Database + authentication | All account and progress data | **EU — Ireland (`aws-0-eu-west-1`)**, confirmed 9 Aug 2026 |
| **Vercel** | Application hosting + edge | Request data in transit; no independent store | Outside Israel (global edge) |
| **Anthropic** and/or **OpenAI** | AI grading of free-text answers | The *text of the submitted report only* | United States |
| **Resend** | Transactional email (invitations, nudges) | Recipient email address | Outside Israel |

### A note on the AI graders

The grading path is deliberately built so the student's identity does **not**
accompany their text: the report is sent for grading, the identifier is not.
The provider therefore receives prose about a synthetic incident, not an
identified person's record. Students are also told in the privacy notice not to
put real personal information into reports.

This is a meaningful data-minimisation control and should be preserved. Anyone
changing the grading call should not "helpfully" start sending a user id along
with it.

---

## 3. The legal test (Section 36 + Privacy Protection (Transfer of Data Abroad) Regulations)

Transfer of personal data outside Israel is permitted where at least one basis
holds. The bases relevant here:

1. The destination country ensures adequate protection;
2. The data subject consented to the transfer;
3. The transfer is **necessary for the performance of a contract** with the data subject;
4. Appropriate contractual safeguards bind the recipient.

---

## 4. The basis relied on

**For the database — the bulk of the personal data — the strongest basis
applies: adequacy (basis 1).**

The Supabase project is hosted in **Ireland (`eu-west-1`)**, confirmed from the
live connection endpoint on 9 August 2026. Ireland is an EU member state, and
EU/EEA countries are recognised under Israeli law as ensuring adequate
protection of personal data. Every account record, progress row and audit entry
therefore rests in an adequate jurisdiction — this is the single most favourable
fact in this document, and it is worth protecting: **migrating the Supabase
project to a US region would silently downgrade the legal basis for the entire
dataset.** Treat the region as a compliance setting, not an infrastructure
preference.

**For the remaining processors: necessity for performance of the contract
(basis 3), reinforced by contractual safeguards (basis 4).**

This covers Vercel (global edge), the AI graders (United States) and Resend.

The service *is* a hosted web application. A student who creates an account to
take the course cannot be served without their credentials and progress being
stored and processed by the hosting and database provider — the processing is
not incidental to the service, it constitutes it. The same holds for the AI
grading of a report the student expressly submits for grading.

Supporting this:

- **Contractual safeguards.** Each processor is engaged under its standard Data
  Processing Addendum, which imposes confidentiality, security and
  sub-processor obligations, and restricts use of the data to providing the
  service. See §5 for the filing status of each.
- **Transparency.** `/privacy` names every sub-processor above and states what
  each receives, so the transfer is disclosed rather than silent.
- **Minimisation.** Only what the service needs is transferred, and the grading
  path is de-identified (§2).

**Not relied on:** adequacy is *not* asserted for the United States (the AI
graders) — only for the EU-hosted database. Consent (basis 2) is not used as a
primary basis anywhere: consent given as a precondition of using a service is a
weak footing, and basis 3 is the honest description of what actually happens.

---

## 5. Action register

| # | Action | Status |
|---|---|---|
| 1 | Execute / file the **Supabase DPA** | ☐ To do |
| 2 | Execute / file the **Vercel DPA** | ☐ To do |
| 3 | File the **Anthropic** and/or **OpenAI** DPA / zero-retention terms | ☐ To do |
| 4 | File the **Resend DPA** | ☐ To do |
| 5 | Record the Supabase project **region** | ☑ **Done** — Ireland (`eu-west-1`), confirmed 9 Aug 2026 from the live endpoint. Do not move it out of the EU without redoing §4. |
| 6 | Add a processor list + this basis to the college contract template | ☐ To do |

Items 1–4 are administrative — each provider publishes a DPA that is accepted
or countersigned online. They are listed as open because *having* one and
*being able to produce it* are different things, and procurement asks for the
second.

**Keep this table honest.** An unticked box is a known gap; a ticked box with no
filed document is worse than either.

---

## 6. On changing processors

Adding a processor that receives personal data means: add it to the table in §2,
add it to `/privacy`, confirm a DPA, and re-check that the basis in §4 still
describes the new flow. A processor added for convenience — analytics, session
replay, a support widget — will usually *not* be covered by "necessary for
performance of the contract", and needs its own analysis before it ships.
