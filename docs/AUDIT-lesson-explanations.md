# Audit — explanation quality across the 34 theory lessons

2026-08-12. Four content auditors read the lessons in full, plus objective
metrics measured over the whole corpus. **Every HIGH finding below was
re-verified against the source by hand** — agents have been wrong in this repo
before, so nothing here is reported on an agent's word alone. The verification
command is given with each one.

## Headline

The corpus is in good shape. Technical accuracy is high: Event IDs, SubStatus
codes, `GrantedAccess` values, Kerberos encryption types and vendor field names
checked out across all 34 lessons, and no fabricated statistics were found.
Vendor naming is current almost everywhere (Entra ID, Defender XDR, Microsoft
Sentinel) — the category most likely to rot silently.

The problems are not "wrong facts". They are **six specific defects** and **one
structural pattern**, listed by what they cost the student.

---

## HIGH — verified, worth fixing

### 1. Lesson #5 is the problem. Three independent findings all land on it.
`windows-event-log-analysis-for-threat-detection` sits at curriculum position
**5**, between two beginner lessons. Four auditors reached it by different
routes and each found a different defect — which is what makes this the top
finding rather than one reviewer's opinion:

**(a) It uses Kerberos vocabulary before Kerberos is taught.** KRBTGT, DCSync,
TGT and Golden Ticket **all make their first appearance in the entire course
here** — in lesson #5. Kerberos itself is taught in lesson **#6**, and
DCSync/Golden Ticket mechanics not properly until **#32**. A student meets
"an adversary who has obtained the KRBTGT account's hash (typically via DCSync)
can forge Ticket Granting Tickets" having never been told what a ticket is.

*Verified:* first-appearance scan across all 34 lessons — every one of those
four terms resolves to lesson #5.

**(b) It requires Splunk SPL three lessons before SPL is taught.** Every worked
example in it is non-trivial SPL (`stats`, `eval`, `join`, `mvcount`, `append`,
subsearches). `siem-fundamentals-and-alert-triage` — which teaches what `index=`
and `stats` mean — is at position **8**. `authentication-identity-kerberos-ntlm`
at #6 has the same problem.

**(c) It is redundant.** Its Kerberos-attack section duplicates lesson #6 and
lesson #32 almost entirely, adding no new material — so it is simultaneously
premature *and* repeated later.

**Recommended fix — one change solves all three:** trim lesson #5's final
section to bare Event-ID pattern recognition (4768/4769/4662 exist and matter)
with an explicit forward pointer to #6 and #32, and move
`siem-fundamentals-and-alert-triage` earlier — to roughly position 4, before
both Windows lessons. That resequencing also fixes every future lesson that
wants to show a query.

*Verify:* `npx tsx scripts/list-lesson-figures.mjs` for order;
`grep -c "index=wineventlog" src/data/builtinLessons.ts` for the SPL.

### 1b. No foundational lesson on hashing, encryption or certificates
**25 of 34 lessons use hashes**, and the course also leans on TLS certificates
and JA3 (#15, #21), DKIM as a "cryptographic signature" (#19), and RC4-vs-AES
ticket encryption as an attack signal (#5, #6, #32). No lesson teaches what a
hash is, why it cannot be reversed, or what a certificate proves.

This matters most at the Pyramid of Pain in #33 — its whole point is that a hash
is trivial for an attacker to change. A student who was never told *why* one
byte-change produces a completely different hash cannot really absorb that.

*Caveat, stated honestly:* my check for "does any lesson explain hashing" is a
crude keyword scan and matched four lessons incidentally. What I can say
confidently is that **no lesson is dedicated to it and none of the 34 section
headings covers it** — not that the word never appears in an explanatory
sentence somewhere.

**Suggested fix:** a short beginner lesson placed after "what a log is" —
hash vs encrypt vs sign, symmetric vs asymmetric at analyst depth, what a
certificate proves. Cheapest change with the widest downstream payoff: it
retroactively strengthens six-plus later lessons without adding detection scope.

### 2. `active-directory-attacks-explained` carries no ATT&CK IDs in its body
It teaches seven techniques in depth. **Zero** of their IDs appear in the body
text — Kerberoasting's appears only in a reference URL:

| Technique | Discussed | ID in body |
|---|---|---|
| Kerberoasting (T1558.003) | yes | no |
| AS-REP Roasting (T1558.004) | yes | no |
| Pass-the-Hash (T1550.002) | yes | no |
| Pass-the-Ticket (T1550.003) | yes | no |
| DCSync (T1003.006) | yes | no |
| Golden Ticket (T1558.001) | yes | no |
| Silver Ticket (T1558.002) | yes | no |

This is inconsistent with `attackTypeLessons.ts`, which puts T-numbers in the
section headings — so a student who learned "Pass-the-Hash = T1550.002" there
gets no reinforcement here, and never sees the other six IDs at all. These are
interview-grade facts.

### 3. `social-engineering-explained` has no concrete artifact anywhere
5 sections, **0 `codeExample` blocks** — the only lesson in its file like that.
It discusses MFA fatigue, T1598 recon mail and help-desk impersonation without
showing a single log line. A student finishes it unable to recognise any of it
in data.

*Fix:* one Entra ID `SigninLogs` example showing repeated push approvals for one
`UserPrincipalName` within minutes, matching the style already used in
`credential-attacks-explained`.

---

## MEDIUM — verified factual corrections

4. **ASR rule count overstated.** `defender-for-endpoint-console` says
   "several dozen more" ASR rules beyond three named. Microsoft's actual set is
   roughly 16–19 rules total. A student who opens the real console finds a much
   shorter list.
   *Verify:* `grep -o "several dozen more" src/data/pathLessons-l.ts`

5. **MITRE tactic count contradicts its own list.**
   `mitre-attack-and-the-cyber-kill-chain` says "fourteen tactics" then names
   exactly **twelve** (TA0001–TA0011, TA0040). Missing: Reconnaissance (TA0043)
   and Resource Development (TA0042) — which matters here specifically, because
   this is the section drawing the Kill-Chain correspondence and those two are
   the ones that map to Reconnaissance/Weaponisation.
   *Verify:* `grep -o "TA00[0-9][0-9]" src/data/pathLessons-e.ts | sort -u`

6. **Stale product name.** `siem-fundamentals-and-alert-triage` lists "Google
   Chronicle"; it is now Google Security Operations. Notable because the same
   curriculum handles "Entra ID, formerly Azure AD" correctly elsewhere — so
   this is an inconsistency, not a house style.

7. **Invalid SPL presented as runnable.** The Sysmon ProcessGuid example uses
   `let root_guid = "..."` — not valid Splunk syntax. Compounding finding #1: a
   student with no SPL grounding yet cannot tell it is pseudocode.

8. **MITRE conflation.** The phishing quiz labels inbox-rule hiding
   "T1564.008 / T1098.002". T1564.008 (Email Hiding Rules) is correct;
   T1098.002 is *delegate permissions* — a different artifact. Teaching them as
   interchangeable is a mapping error a student carries into an interview.

---

## The structural pattern — and it is mine

Measured across the corpus (`scripts/lesson-readability.mjs`):

| | 10 lessons added this session | 24 pre-existing |
|---|---|---|
| avg words | **3,790** | 2,874 |
| avg paragraphs over 140 words | **10.9** | 3.0 |
| avg quiz questions | **3.2** | 4.0 |
| avg sections | 6.4 | 5.0 |

The lessons I wrote this session are **32% longer, carry 3.6× as many
oversized paragraphs, and ask fewer quiz questions** than the corpus they joined.
Two are extreme outliers on length (`active-directory-attacks-explained` +47%,
`firewall-and-network-defence` +42%).

Three of the four auditors independently flagged "dense long-form prose, no
in-body lists" as a cross-cutting weakness — concentrated in exactly those
lessons. That is corroboration from a different method, not a coincidence.

A related measurement: **0 of 184 sections** contain a bullet or numbered list in
their prose. Where structure exists, it lives in the `codeExample` box. Students
who read the text and skim the code box miss the frameworks entirely — the
five-question framework, the three-way verdict, the six query verbs are all
list-shaped ideas rendered as paragraphs.

---

## What the auditors agreed is genuinely strong

Worth protecting, not just fixing:

- **Every tool lesson teaches limitations, not just features.** RTR ≠ containment,
  Rollback ≠ undoing exfiltration, Detect-only ≠ protection, high Secure Score ≠
  secure, "allow" ≠ safe. None read as a vendor brochure.
- **The judgment lessons are unusually actionable** — checklists and thresholds
  rather than "be curious". `the-analyst-mindset` holds three competing
  hypotheses and shows two getting killed by evidence.
- **`the-investigation-workflow` and `writing-the-incident-report` thread one
  case (WKS-4471) across sections to a decision.** This is the model the weaker
  lessons should copy.

---

## Also found — lower severity

- **Duplication: DNS tunnelling and HTTPS beaconing** are taught with nearly the
  same SPL and prose in lesson #15 and again in #21, six apart, neither
  cross-referencing the other. Fix by having #21 recap-and-link, spending the
  reclaimed space on the exfiltration pipeline (T1074/T1560/T1041/T1048/T1567),
  which no lesson currently owns.
- **`topic` field format is inconsistent.** The 6 attack-type lessons and the
  playbook lesson use a full sentence where the other 27 use a short label. If
  `topic` ever renders as a badge, those 7 will look like a different course.
- **Missing false-positive caveats** on several attack signatures: shared
  NAT/VPN egress IPs look exactly like password spraying; stale cached
  credentials produce the same 4625 burst as brute force; authorised pentests
  produce the "storm of 400s ending in one 200" web pattern; DR/backup tests can
  fire the `vssadmin delete shadows` signal. Each needs one sentence.
- **SSRF-to-cloud-metadata omits IMDSv2**, the control that actually blocks the
  basic version of that attack today.

## Recommended order of work

1. **Fix lesson #5** (finding #1) — trim its Kerberos section to Event-ID
   recognition and move the SIEM lesson earlier. One array edit plus one section
   rewrite; resolves an orphan-term violation, a prerequisite violation and a
   duplication in a single change. Highest leverage in the whole audit: this is
   the earliest point a student is likely to feel lost.
2. **Add the seven ATT&CK IDs to the AD lesson** (#2) — small, high value.
3. **Fix the four factual items** (#4–#8) — each a one-line correction.
4. **Give `social-engineering-explained` one real artifact** (#3).
5. **Add the foundational crypto lesson** (#1b).
6. **Break the oversized paragraphs in the 10 new lessons and lift frameworks
   out of the code boxes into real lists.** Largest effort, and the one that
   most improves how the course *reads*.

Items 1–4 are surgical and safe. Items 5–6 are genuine authoring work and should
be scoped separately.

## Under-modelled everywhere (a theme, not a defect)

Several auditors landed on the same gap independently: worked examples tend to
show cases where **all signals agree**. The severity method, the C2 thresholds
and the spray/brute-force signatures all illustrate clean cases. Real analysts
get stuck on conflicting evidence — a high-criticality asset with weak certainty,
a `cv` of 0.25 just outside the threshold, a shared NAT egress IP that looks
exactly like spraying. Adding one deliberately ambiguous worked case per
judgment lesson would be the highest-value content addition after the fixes
above.
