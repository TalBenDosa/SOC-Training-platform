# Curriculum Plan — framework-grounded syllabus & gap analysis

*Built from a verified research pass over the canonical curriculum frameworks (2026-07-19).
Every claim below is labelled by evidence strength. Read the "What the research could NOT
establish" section before treating any of this as settled.*

---

## 1. What the research actually established

25 candidate claims were adversarially verified (3 independent verifiers each; a claim needed
2/3 to survive). **16 confirmed, 9 refuted.** The honest headline:

> The frameworks give a strong, citable answer to **WHAT** must be taught and to **which authority**
> it maps. They give **almost no** answer to **ORDER, HOURS, or PRACTICE-RATIO** — and two of them
> refuse to, on purpose.

### Confirmed (high confidence, primary sources)

| # | Finding | Source |
|---|---|---|
| F1 | **ACM/IEEE CSEC2017** defines the body of knowledge as exactly **8 knowledge areas** — Data, Software, Component, Connection, System, Human, Organizational, Societal Security — organised by *object of protection*, not by job function or attack/defence. | CSEC2017 §4.1–4.8 |
| F2 | CSEC2017 imposes a **mandatory floor**: the "essential concepts" of *every one* of the 8 KAs must be covered by *every* program regardless of specialisation — "the minimum required content for any cybersecurity program". | CSEC2017 ch.3, ch.6 |
| F3 | CSEC2017 prescribes **6 crosscutting concepts** threaded through the KAs, never taught standalone: Confidentiality, Integrity, Availability, Risk, **Adversarial Thinking**, **Systems Thinking**. | CSEC2017 §3.2.2 |
| F4 | **NSA/NCAE-C CAE-CD (Dec 2024)** defines the most concrete technical spine: 3 mandatory Foundational KUs (IT Systems Components, Cybersecurity Fundamentals, Cybersecurity Principles) + 5 technical Core KUs = **Basic Scripting & Programming, Basic Networking, Network Defense, Basic Cryptography, Operating Systems Concepts**. | CAE-CD KU doc p.2–3 |
| F5 | **CAE-CD places SOC/blue-team detection in the MANDATORY CORE, not electives.** The Network Defense KU explicitly requires SIEM, log analysis, network security monitoring (NOCs/SOCs), network traffic analysis, traffic signature analysis, network anomaly detection, and the **MITRE D3FEND matrix**. | CAE-CD p.22 (verbatim topic list) |
| F6 | CAE-CD seeds **SIEM/SOAR and log analysis inside *Basic Networking* (topics 10–11), one tier before Network Defense** — the closest thing to framework support for "networking before detection". | CAE-CD p.18 |
| F7 | **NIST NICE SP 800-181r1** supplies Task/Knowledge/Skill statements as **learning objectives** (not just HR classification) — but supplies **no sequencing, prerequisites, hours or pedagogy**. | NIST SP 800-181r1 |
| F8 | **ENISA ECSF** defines exactly **12 role profiles**. There is **no "SOC Analyst" profile** — it is an *alternative title* under **Cyber Incident Responder**, whose required knowledge embeds OS security and network security. | ENISA ECSF v1.0 |
| F9 | Both CSEC2017 **and** CAE-CD **deliberately refuse to prescribe hours or credits**. CAE-CD instead defines depth by learning outcomes + a **75% topic-coverage floor** per KU. | CSEC2017 / CAE-CD p.3 |
| F10 | The one surviving pedagogy finding: **adaptive, branching difficulty** in hands-on cyber-range training does not overwhelm students the way a single static sequence does. *(n=24, single institution, KYPO — suggestive, not an evidence base.)* | IEEE FIE 2021 |

### What the research could NOT establish — and what was actively refuted

This matters more than the confirmations, because these are exactly the things a syllabus author
most wants:

- **No verified hour/proportion data.** Not from CSEC2017, not from CAE-CD (both refuse), and the
  university-catalogue study that offered them was **refuted 0-3**. Anyone publishing "the correct
  hour split across security domains" is not citing an authority — because no authority provides one.
- **No verified prerequisite graph.** The module order in §2 is *reasoned inference from framework
  content*, not an evidence-backed sequence. **CAE-CD specifies a required SET, not an ORDER**
  (claim to the contrary refuted 0-3).
- **"CSEC2017 endorses a spiral curriculum" — REFUTED 0-3.** The word "spiral" appears nowhere in
  CSEC2017. It says "introduced early and reinforced throughout"; the spiral framing is an analyst gloss.
- **No verified practice-to-theory ratio, and no verified evidence** that performance-based exams
  predict on-the-job performance better than multiple-choice. Nothing survived on this.
- **No verified add/drop or skills-gap data** to justify reweighting toward AI security, cloud-native,
  identity-first or supply chain.
- **CyBOK/SFIA as canonical — refuted 0-3.** Their status is genuinely unresolved, so CyBOK's absence
  here is a known open gap, not a judgment that it is unimportant.

**Practical consequence for this platform:** we should stop looking for an authoritative hour
allocation and instead define depth the way CAE-CD does — **by learning outcomes plus a coverage
floor** — which is both defensible and cheaper to verify.

---

## 2. Framework-derived module sequence

*Confidence: LOW as a sequence (inference), HIGH as a content set (each module cites a framework).
Presented as a reasoned default, not an evidence-backed order.*

| Module | Content | Justified by |
|---|---|---|
| **M0 Foundations** | IT systems components, cybersecurity fundamentals & principles | CAE-CD Foundational (all 3 required); CSEC2017 System Security essentials |
| **M1 Networking** | Protocols, traffic, *plus* first exposure to SIEM/log analysis | CAE-CD BNW (incl. topics 10–11); CSEC2017 Connection Security |
| **M2 Operating Systems** | Windows/Linux internals, OS security | CAE-CD OSC; CSEC2017 System/Component Security; ECSF Cyber Incident Responder |
| **M3 Scripting & Programming** | Automation, parsing, tooling | CAE-CD BSP (**mandatory core**); CSEC2017 Software Security |
| **M4 Cryptography** | Primitives → PKI/TLS applications | CAE-CD BCY (**mandatory core**); CSEC2017 Data Security |
| **M5 Network Defense / SOC ops** | SIEM, log analysis, NSM, traffic & anomaly analysis, **D3FEND** | CAE-CD NDF (**mandatory core**, verbatim); NICE Defensive work roles; ECSF |
| **M6 Incident Response** | IR lifecycle, CSIRT/SOC operation | ECSF Cyber Incident Responder; NICE IR work role |
| **M7 Human / Organizational / Societal** | Human factors, risk, policy, legal, ethics, privacy | CSEC2017 **mandatory essentials**; CAE-CD non-technical core KUs |
| **Threaded throughout** | CIA, Risk, **Adversarial Thinking**, **Systems Thinking** | CSEC2017 §3.2.2 — explicitly *not* a standalone module |

---

## 3. Gap analysis — this platform vs the frameworks

Current inventory: **~68 rooms**. Coverage is extremely uneven when mapped onto the framework.

### Where the platform is strong (and framework-validated)

| Module | Rooms | Verdict |
|---|---|---|
| **M5 Network Defense / SOC ops** | SIEM 8 · Threat Detection 7 · SOC Operations 7 · Log Analysis 4 | **Best-in-class.** F5 confirms this is *mandatory core*, not an elective — the platform's central bet is correct. |
| **M1 Networking** | Network Security 11 (incl. new advanced protocol tier) | Strong, now with real depth. Matches F6 ordering. |
| **M2 Operating Systems** | Endpoint 7 + Windows/Linux/AD rooms | Solid. |
| *(beyond framework core)* | Cloud 8 · Threat Intel 6 | Strong differentiators. |

### Genuine gaps — ordered by framework authority

| Gap | Severity | Why it matters |
|---|---|---|
| **M3 Scripting & Programming — ZERO rooms** | 🔴 **Critical** | A CAE-CD **mandatory technical core KU**. A technical-track program cannot be validated without it. Also CSEC2017 Software Security. |
| **M4 Cryptography — ZERO rooms** | 🔴 **Critical** | The other missing CAE-CD **mandatory core KU**. The new TLS room teaches *applied* TLS but never the primitives beneath it. |
| **CSEC2017 Software Security (AppSec)** | 🟠 High | No secure coding, no OWASP, no web-app vulnerability classes. One of the 5 technical KAs — currently absent. |
| **CSEC2017 Societal Security** | 🟠 High | Cyber law, ethics, privacy, cybercrime — **mandatory essentials** (F2). Currently zero coverage. |
| **CSEC2017 Organizational Security** | 🟠 High | Risk management, policy/compliance, security program management. Only partial (Escalation, Reporting, Customer Comms). |
| **CSEC2017 Human Security** | 🟡 Medium | Social engineering *as human factors* and usable security. Phishing Analysis covers detection, not the human dimension. |
| **CSEC2017 Component Security** | 🟡 Medium | Hardware/supply-chain security. Only touched inside an edge-case room. |
| **M0 Foundations — 1 room** | 🟡 Medium | Thin entry tier for absolute beginners (see difficulty skew below). |

### Structural finding: the difficulty skew

Before batch 17: **41 intermediate / 14 beginner / 7 advanced**. The platform is "fat in the middle" —
too few first steps for a true beginner, and (until now) too little to climb into. Batch 17 helps the
top; **M0/M3/M4 would fix the bottom.** F10 (adaptive branching difficulty beats a static sequence)
is the one piece of pedagogy evidence we have, and it argues for widening the entry tier rather than
lengthening the middle.

---

## 4. Recommended build order

Ranked by *framework authority × current absence* — not by ease.

1. **Cryptography track (M4)** — closes a mandatory CAE-CD core KU. Primitives → hashing → symmetric/
   asymmetric → PKI → certificate validation, feeding directly into the existing TLS room.
2. **Scripting & Automation track (M3)** — the other mandatory core KU. Frame it as an analyst tool:
   log parsing, regex, enrichment scripting, API queries — not generic programming.
3. **Application Security track** — CSEC2017 Software Security KA. OWASP Top 10 as *detection* content
   (what web attacks look like in logs/WAF) plays to the platform's existing strength.
4. **Governance / Societal track** — risk, policy, legal, ethics, privacy. Satisfies three CSEC2017
   mandatory-essential KAs at once and is currently the single largest blind spot.
5. **Widen M0 Foundations** — more true-beginner on-ramps, per the difficulty skew + F10.

**Depth standard for new content (adopting CAE-CD's method, F9):** define each room by explicit
learning outcomes and require **≥75% topic coverage** of its mapped KU — rather than inventing an
hour budget no framework supports.

**Two things to keep doing, now with citations:**
- The **no-hints / reason-it-yourself** design is CSEC2017's **Adversarial Thinking** crosscutting
  concept (F3) — a first-class curricular requirement, not a stylistic choice.
- **Difficulty tiers / adaptive paths** are supported by the only surviving pedagogy finding (F10).

---

## 5. Open questions worth a second research round

- Where can defensible hour/proportion data actually be sourced? (Candidates: ABET cybersecurity
  program criteria, SANS/GIAC contact hours, published university degree plans.)
- Do performance-based assessments predict on-the-job performance better than MCQ? *Nothing survived.*
- Should **CyBOK** (NCSC-backed, ~21 KAs) be cross-mapped? Its canonical status was refuted, leaving
  it genuinely unresolved.
- Does the **2025 CSEC2017 Supplement** (6 foundational KAs, 74 learning outcomes) govern our
  beginner tier instead of the 8-KA model?
