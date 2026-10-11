# How a SOC Team Training Exercise Should Be Built — Deep Research & Upgrade Roadmap

**Date:** 2026-09-23
**Scope:** What the evidence says a *team* SOC exercise must contain (and must avoid) to actually
build competent, coordinated analysts — then mapped onto the current **Team-SOC ("HACK THE SOC")**
feature, with a prioritized roadmap to take it to a best-in-class level.
**Method:** Web research across authoritative frameworks (NIST, FEMA/HSEEP, NIMS/ICS) and
peer-reviewed team-performance / learning science (Salas, Tannenbaum, Edmondson), cross-walked
against this feature's prior audits (QA-2026-09-18, INFRA-2026-09-18, AGENT-PLAYTEST-2026-09-19,
CONTENT-AUDIT-2026-09-21).

> **One-line thesis.** A SOC *team* exercise is not "a single-player shift with more people in the
> room." It is a **coordination instrument**: its whole job is to force — and then measure — the
> team behaviours (shared picture, closed-loop handoffs, mutual backup, leadership under pressure)
> that decide real-incident outcomes. The current feature has an unusually strong *content* engine
> and already implements several of these behaviours; the highest-leverage upgrades are about
> **making coordination unavoidable, observable, and debriefable**.

---

## Part 0 — The research questions

Framing the work as questions keeps the answers honest. The ones that drove this research:

1. **What is a team exercise even for?** How does it differ from individual practice, and what does
   "success" mean for a *team* (vs a solo analyst)?
2. **Which team behaviours actually predict performance**, and can a training exercise reliably
   *elicit* them? (If a behaviour never gets a chance to happen, it can't be trained or scored.)
3. **How should the scenario be structured** — one incident or several? How fast? How long? How much
   noise? How scripted vs emergent?
4. **How do you inject pressure and curveballs** without a live facilitator typing constantly?
5. **What makes the debrief actually change behaviour** (the single most evidence-backed lever)?
6. **What must be measured**, and what metrics mislead?
7. **What kills a team exercise** — the anti-patterns to design out?
8. **What raises the ceiling** — what do the best programs do that a good one doesn't?

Each is answered below, then turned into concrete changes.

---

## Part 1 — What a team exercise is *for* (and how it differs from solo practice)

**Finding.** Frameworks converge on a spectrum of exercise types with escalating fidelity:
discussion-based **tabletop** exercises (talk through roles/decisions) → **functional** exercises
(people actually execute their roles against a simulated event) → full-scale. NIST SP 800-84 defines
this progression and stresses that functional exercises "allow staff to execute their roles and
responsibilities as they would in an actual emergency situation, but in a simulated manner"
([NIST SP 800-84, CSRC](https://csrc.nist.gov/pubs/sp/800/84/final);
[NIST SP 800-84 PDF](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-84.pdf)).
This feature is a **functional** exercise — the highest-value, hardest-to-fake tier.

**Finding.** The specific value of *team* practice is the seam, not the task. Cyber-range research
is blunt: "generic training programs miss the collaborative dynamics essential to effective security
operations… when training addresses these roles in isolation without practicing critical
communication and handoff points, teams struggle to work together effectively under pressure"
([OffSec — cyber ranges](https://www.offsec.com/blog/enterprise-cyber-training-ranges/)). Incident
response exercises exist to "practice interactions between SOC analysts, network administrators,
legal teams, and executive leadership, improving communication flow and decision-making."

> **Answer to Q1.** Solo practice trains *detection and analysis*. A team exercise trains
> *coordination* — handoffs, shared situational awareness, prioritisation across concurrent work,
> and leadership under pressure. If your team mode only makes people do solo analysis side-by-side,
> you've built a louder single-player mode. **The exercise must make coordination the bottleneck.**

**Where this feature stands.** Strong. It already has 4 differentiated roles (Tier-1 ×N, Tier-2 ×N,
Tier-3, SOC Manager), an explicit T1→T2→T3 escalation chain, a manager coordinating two concurrent
incidents, and MSEL management-pressure beats. It is genuinely a functional team exercise, not
parallel solitaire.

---

## Part 2 — The behaviours that predict team performance (and how to elicit each)

The most cited synthesis of *what makes teams effective* is Salas, Sims & Burke's **"Big Five"**:
**team leadership, mutual performance monitoring, backup/mutual-support behaviour, adaptability, and
team orientation** — held together by three **coordinating mechanisms: shared mental models, mutual
trust, and closed-loop communication**
([Salas, Sims & Burke 2005, *Small Group Research*](https://journals.sagepub.com/doi/10.1177/1046496405277134);
[overview](https://www.researchgate.net/publication/220041354_Is_there_a_Big_Five_in_Teamwork)).

A design rule follows directly: **for every behaviour you want to train, the scenario must create a
moment where that behaviour is the only way through.** Below, each Big-Five element is mapped to a
concrete exercise mechanic and to this feature's current state.

| Behaviour (Salas) | The moment that forces it | Current feature | Gap / upgrade |
|---|---|---|---|
| **Closed-loop communication** (say → acknowledge → confirm done) | A handoff that is *rejected/bounced* and must be re-sent with more evidence | ✅ T2→T3 elevation requires ≥8-char `hunt_ask`; T2 "bounce" back to T1; ack-gated | Score the **loop closing**, not just the send. Reward acknowledged-and-actioned handoffs; flag opened-but-never-closed ones (see Part 6). |
| **Shared mental models** (everyone holds the same picture) | A shared incident board that only stays correct if people update it | ✅ SharedCase + SituationBoard (presence, per-analyst load, MTTA, oldest-unacked) | Add a **shared incident timeline / common operating picture** that the team co-builds; measure divergence (two analysts, contradictory verdicts on the same entity). |
| **Mutual performance monitoring** (I can see if a teammate is drowning) | Visible per-teammate workload + an alert when someone is overloaded | ✅ SituationBoard shows per-analyst load & oldest-unacked | Turn passive display into an **active prompt**: "T1-Dana has 6 un-acked highs — reassign?" surfaced to the Manager. |
| **Backup / mutual support** (I take work off an overloaded teammate) | Reassignment must be possible *and rewarded* | ✅ Manager reassign; queue strip | Add a **team credit** for load-balancing: a case picked up from an overloaded peer scores the team, not just the individual. |
| **Team leadership** (someone sets priorities under pressure) | Two live incidents → the Manager must sequence them; pressure injects demand SITREPs | ✅ 2 concurrent incidents (med/hard); 3 mgmt-pressure MSEL beats; Manager AAR | Give the Manager an explicit **prioritisation decision** that has consequences (choose which incident to resource first; the other worsens if starved). |
| **Adaptability** (the plan changes mid-incident) | A curveball that invalidates the current hypothesis | ⚠️ MSEL beats add pressure but rarely *change the technical picture* | Add **branching injects**: e.g., "the 'contained' host just beaconed again" — forcing re-scoping. |
| **Team orientation / trust** (safe to ask, safe to be wrong) | No-fault framing; errors are learning, not scoring traps | ⚠️ Partial (AAR exists) | See Part 5 (psychological safety) — the single cheapest high-impact change. |

> **Answer to Q2.** Yes — the Big Five behaviours predict performance and can be elicited *by design*.
> The feature already elicits most of them. The two under-served ones are **adaptability**
> (technical branching, not just pressure) and **team orientation / psychological safety**.

---

## Part 3 — Scenario structure: concurrency, pacing, duration, noise

**One incident or several?** Concurrency is what creates the coordination bottleneck and the
leadership decision. This feature already runs **two concurrent stories** on medium/hard (single-threaded
on easy for beginners) — this is correct and evidence-aligned: it removes the "one incident drains
to the whole team" dead time and forces prioritisation.

**How fast / how long?** NIST SP 800-84 gives concrete envelopes: operational-level exercises run
"two to eight hours," and it recommends pairing a training session with any exercise over four hours
([NIST SP 800-84](https://csrc.nist.gov/pubs/sp/800/84/final)). A short web-delivered functional
exercise doesn't need hours — but **the advertised duration and the real duration must agree.**
The 2026-09-21 content audit found the feed *streams* only ~7 minutes while the lobby promised
"~30–45 min," so after ~7 min no new telemetry arrives and the sustained-vigilance rhythm of a real
shift is never exercised. The briefing text was corrected to ~20–30 min and the benign pools/cadence
were rebalanced (medium 42→90 events, gaps widened) — **this was the right fix and should be
verified end-to-end** (a live shift's value is partly in *sustained* attention, not a 7-minute burst).

**How much noise?** Realistic signal-to-noise is what trains *recognition* — "teams that regularly
practice threat detection in simulated environments develop pattern recognition skills that
translate to quicker identification of real threats… reducing dwell time"
([OffSec](https://www.offsec.com/blog/enterprise-cyber-training-ranges/)). The content audit
confirmed strong noise depth (415-event generic pool + per-company pools, 33 event types, 24 vendors).
Keep this — it is a genuine differentiator.

**Scripted vs emergent.** The answer is *both*, and the mechanism is the MSEL (next section).

> **Answer to Q3.** Concurrency = yes (already done). Duration = make the promise and the pacing
> agree (fixed; verify). Noise = already strong. The remaining structural upgrade is **branching**
> the scripted layer so the incident can *change shape* (Part 4).

---

## Part 4 — Injecting pressure and curveballs without a live facilitator (the MSEL)

**Finding.** The professional instrument for this is the **Master Scenario Events List (MSEL)** from
FEMA's HSEEP — "an online timeline of expected actions and scripted events (injects) designed to
test exercise objectives and drive continual exercise play." Each MSEL entry is richly structured:
**event number, scenario time, inject type & delivery method, who delivers it, the intended
recipient, the message, the *expected participant response*, the *linked exercise objective*, and a
controller notes field** ([FEMA HSEEP MSEL overview](https://preptoolkit.fema.gov/web/help/hseep-user-guides/-/knowledge_base/hseep-written-guides/msel-overview);
[creating MSEL injects](https://preptoolkit.fema.gov/web/help/hseep-user-guides/-/knowledge_base/hseep-written-guides/creating-msel-events-injection);
[FEMA HSEEP](https://www.fema.gov/txt/media/factsheets/2010/hseep.txt)). Controllers "manage the
flow and pace… deliver injects according to the MSEL… and can pause or redirect play."

**Where this feature stands.** It already has an automated MSEL: `buildTimeline.ts` places 5 scripted
injects (3× management-pressure, 1 vishing ticket, 1 announcement) at fractions of the shift span,
promoted by pg_cron — so tempo and curveballs don't depend on a live facilitator. This is exactly the
HSEEP pattern, automated. **Excellent foundation.**

**The gaps, measured against the HSEEP inject schema:**

1. **Injects don't carry an *expected response* or a *linked objective*.** HSEEP injects always do —
   it's what makes them *evaluable*. Today the mgmt-pressure beats are prompts with no graded
   expected action. **Upgrade:** attach to each inject an `expected_response` (e.g., "Manager posts a
   SITREP within N minutes") and a `linked_objective` (which rubric cell it feeds), so the AAR can
   report "3/5 injects handled."
2. **Injects are *pressure*, not *plot*.** They ask for status; they don't change the technical
   truth. **Upgrade (highest-value):** add **branching / conditional injects** that alter the
   incident — "the host you isolated 4 min ago just made an outbound connection" (forces
   re-scoping / adaptability), or a **false lead** the team must reject (trains discrimination, not
   just detection). This is the one change that most raises fidelity.
3. **No graceful "controller" seat.** HSEEP separates *controllers* (drive pace) from *evaluators*
   (score, stay neutral). This feature auto-controls via pg_cron, and the SOC Manager partly plays
   controller. **Optional upgrade:** an instructor "inject now / pause / add curveball" panel already
   partly exists (InstructorPanel) — extend it to fire from a small MSEL library on demand, so a
   human facilitator *can* step in when present, without being *required*.

> **Answer to Q4.** The automated MSEL is the right architecture and already implemented. Make each
> inject **evaluable** (expected response + linked objective) and let some injects **branch the
> incident**, not just apply pressure.

---

## Part 5 — The debrief is the highest-ROI component (and how to make it work)

**Finding — this is the strongest evidence in the entire literature.** Tannenbaum & Cerasoli's
meta-analysis (46 samples, N≈2,136) found structured debriefs / after-action reviews **improve
performance by ~25% over controls (d≈.67)** — and crucially, that **structure, facilitation, and
alignment** (the debrief maps to the objectives) are what make them work
([Tannenbaum & Cerasoli 2013, *Human Factors*](https://journals.sagepub.com/doi/abs/10.1177/0018720812448394);
[PubMed](https://pubmed.ncbi.nlm.nih.gov/23516804/);
[practitioner guide (PDF)](https://cdn.ymaws.com/www.odnetwork.org/resource/resmgr/2013_education/tannenbaum_using_debriefs_ha.pdf)).
A debrief is not paperwork after the exercise — for a *team* exercise it is where the learning
actually happens.

**Finding — psychological safety is the precondition for the debrief to work.** Edmondson's
foundational research found that *better* teams report *more* errors, not fewer — because
"learning behavior mediates the relationship between team psychological safety and team performance":
good teams surface mistakes and learn; unsafe teams bury them
([Edmondson 1999, *ASQ*](https://journals.sagepub.com/doi/abs/10.2307/2666999);
[AAMC interview](https://www.aamc.org/news/amy-edmondson-psychological-safety-critically-important-medicine)).
For a training tool this means: **the exercise must be framed no-fault, and the debrief must reward
surfacing/correcting an error, not just being right the first time.**

**Where this feature stands.** It has a team AAR (`TeamReport`/`computeReport`), role-specific
rubrics, deterministic replay (a given seed always reproduces the same incident — so the AAR can
*reconstruct the shift exactly*, which is a genuine asset most platforms lack), and the SOC Manager
sees a whole-team AAR.

**Upgrades to hit the evidence:**

1. **Make the AAR *conversational and structured*, not just a scorecard.** The proven format is a
   facilitated arc: *What was supposed to happen? What actually happened? Why the gap? What do we do
   differently?* Add these four framings to the report (per-incident), pre-filled from the event log
   (deterministic replay makes this possible for free), so the team debriefs against ground truth.
2. **Reconstruct the coordination timeline, not just individual scores.** Show the actual handoff
   chain: alert fired → T1 triaged at 00:42 → escalated to T2 at 02:10 → elevated to T3 at 05:30 →
   Manager SITREP at 06:00. This is the team's *closed-loop communication* made visible — the single
   most useful artefact for a team debrief.
3. **Reward error-correction (psychological safety in the scoring).** Add a rubric signal for
   "caught and reversed a wrong verdict" and *do not* punish an early wrong call that was corrected.
   Frame the whole report as "shift review," never "your failures."
4. **Alignment:** ensure every rubric cell traces to a stated objective shown in the lobby briefing
   ("today you're being assessed on: triage accuracy, handoff quality, prioritisation, SITREP
   cadence"). Tannenbaum's data says this alignment measurably boosts the debrief's effect.

> **Answer to Q5.** Keep and *deepen* the AAR — it's the highest-ROI part. Make it a structured,
> ground-truth, coordination-timeline debrief, framed no-fault, with alignment to pre-stated
> objectives.

---

## Part 6 — What to measure (and what misleads)

**Finding — the real SOC metrics.** Detection: **MTTD**. Response: **MTTA** ("how quickly an analyst
picks up an alert after it fires — critical for 24×7 operations where shift handoffs introduce
delays"), **MTTR**, and **escalation rate**. Operational: per-analyst throughput
([CyberDefenders — SOC metrics](https://cyberdefenders.org/blog/soc-metrics-for-analyzing-soc-performance/);
[Splunk — IR metrics](https://www.splunk.com/en_us/blog/learn/incident-response-metrics.html);
[UnderDefense](https://underdefense.com/blog/soc-metrics/)). Critically for a *team* exercise:
"when MTTR stretches, it usually means **handoffs are unclear**… a reduced MTTR indicates
well-defined workflows with minimal handoff delays and clear accountability"
([Palo Alto — MTTR](https://www.paloaltonetworks.com/cyberpedia/mean-time-to-repair-mttr)). So MTTR
and handoff clarity are the same signal.

**Finding — the trap.** Per-analyst counts ("tickets closed per analyst") "identify coaching
opportunities and high performers" — but in a *team* exercise, over-weighting individual throughput
**punishes the exact backup/load-balancing behaviour you're trying to train** (an analyst who takes
a teammate's overflow looks "slower"). Individual metrics must be *team-contextualised*.

**Where this feature stands.** Already computes live MTTA, oldest-unacked, per-analyst load
(SituationBoard); and the playtest work added **ground-truth escalation precision / team recall**
(replacing the earlier ack-based precision, relabeled "handoff coordination") and valid-IOC
filtering, plus a deterministic **hunt-quality** score. This is a sophisticated measurement layer.

**Upgrades:**

1. **Add team-level MTTD / MTTR / handoff-latency** as first-class AAR numbers (time from alert →
   first triage → escalation → containment decision), computed from the event log. These are the
   metrics a real SOC lead recognises, and they *are* the coordination signal.
2. **Handoff-quality score = loop closure.** Reward handoffs that are acknowledged and actioned;
   count "opened but never closed" as the defect. (You already gate acks — surface the closure rate.)
3. **Team-contextualise individual throughput** so backup behaviour scores positively (Part 2).
4. **Span-of-control sanity.** NIMS/ICS holds effective span of control at **3–7** direct reports
   ([USDA NIMS Lesson 2](https://www.usda.gov/sites/default/files/documents/NIMLesson02.pdf)). Use it
   as a coverage/pacing check: if one Manager is coordinating >7 active analysts or a Tier is handling
   too many concurrent cases, that's an overload condition worth surfacing (ties into the existing
   coverage auto-pause logic).

> **Answer to Q6.** Measure **MTTD / MTTA / MTTR / escalation-rate / handoff-loop-closure at the team
> level**, contextualise individual counts so backup isn't penalised, and treat MTTR/handoff latency
> as the coordination KPI. Avoid raw per-analyst leaderboards in a team context.

---

## Part 7 — Anti-patterns: what a team exercise must NOT do

Synthesised from the frameworks and this feature's prior audits:

1. **Parallel solitaire.** Multiple people doing independent solo analysis with no forced handoff.
   *Design out by:* making escalation the only path to resolution for the hard case, and scoring the
   team, not the sum of individuals. (This feature already largely avoids it.)
2. **Promise ≠ reality (duration/pacing).** Advertise 45 min, run 7. Erodes trust and skips the
   sustained-vigilance rhythm. *Fixed in the content-audit batch; verify.*
3. **Pressure without plot.** Injects that only nag for status but never change the technical
   picture — trains SITREP-writing but not adaptability. *Add branching injects (Part 4).*
4. **Un-evaluable injects.** An inject with no expected response and no linked objective can't be
   debriefed. *Add the HSEEP fields (Part 4).*
5. **Scoring that punishes good team behaviour.** Rewarding raw individual throughput, or punishing
   an early wrong verdict that was corrected. *Team-contextualise; reward error-correction (Parts 5–6).*
6. **A scorecard instead of a debrief.** The 25% gain is in the *structured, facilitated* review,
   not the number. *Deepen the AAR (Part 5).*
7. **No psychological safety.** "Gotcha" framing suppresses the error-surfacing that Edmondson shows
   is what good teams actually do. *Frame no-fault; reward surfacing (Part 5).*
8. **Facilitator-dependence.** Requiring a human to type injects doesn't scale to self-serve.
   *Already solved via the automated MSEL + pg_cron — keep it, add an optional human override.*
9. **Common-terminology drift.** NIMS/ICS stresses "standard or common terminology… essential to
   efficient, clear communications" ([USDA NIMS Lesson 1](https://www.usda.gov/sites/default/files/documents/NIMLesson.pdf)).
   *Ensure role labels, severities, and handoff verbs are consistent across every console and the AAR.*
10. **Content repetition at the top tier.** A class running "hard" repeatedly at a company with only a
    handful of advanced stories sees the same incidents. *Content audit flagged QuantumBank(4)/
    RocketStack(8); partially mitigated by the hard→core fallback — deepen the advanced pools
    (the paused "4–6 advanced scenarios" task addresses exactly this).*

---

## Part 8 — Raising the ceiling: what best-in-class programs add

**Finding — evaluation is a discipline, not a screen.** Serious cyber-range evaluation uses
structured, multi-dimensional criteria: the **TARGET taxonomy** defines 75 cyber-range-exercise
evaluation criteria across eight dimensions, *including team- and leadership-effectiveness*
([Train as you Fight, CHI '23](https://dl.acm.org/doi/fullHtml/10.1145/3544548.3581046)). Recent
work (**t1ger**) integrated a learning-management layer into a *commercial* SOC's cyber range and
validated it in a controlled empirical study — i.e., the frontier is *measuring learning impact*, not
just running scenarios ([t1ger, CHI '26](https://doi.org/10.1145/3772318.3791226)).

**Finding — grounding content in real threat intel.** Best programs anchor scenarios in ATT&CK
techniques and real APT TTPs so recognition transfers to the field. This feature already maps 120
MITRE technique IDs across all tactics (content audit) — a real strength. Keep content **current**
(a freshness cadence is itself a differentiator).

**Ceiling-raising upgrades, in order of leverage:**

- **Branching MSEL + false leads** (adaptability + discrimination). *Highest fidelity gain.*
- **Structured, ground-truth AAR with the coordination timeline** (the 25% lever). *Highest learning
  gain.*
- **Team-level MTTD/MTTR/handoff-closure metrics** (recognisable, coordination-true). *Highest
  credibility gain.*
- **A shared common-operating-picture the team co-builds** (shared mental model made explicit).
- **Objective alignment shown in the lobby → scored in the AAR** (cheap, measurably boosts debrief).
- **No-fault framing + error-correction credit** (cheapest high-impact change).
- **Deepen advanced content pools** for hard-tier variety (the paused scenario-authoring task).

---

## Part 9 — Prioritized upgrade roadmap

Ranked by (impact on real team-training outcomes) ÷ (effort), grounded in the sections above.

> **✅ Implementation status (2026-09-23) — the P0–P2 roadmap below is IMPLEMENTED** (staging-only,
> all gates green). Summary:
> - **P1 work-division prerequisites** (from the SPEC, Salas mutual-monitoring/backup): active
>   overload nudge (`coordination.nudge`, migration 0068), backup rubric cell, "Take next" pull,
>   span-of-control guard, orphan-item badge. See `SPEC-team-role-division.md` §7.
> - **P0 (AAR):** structured 4-question debrief arc (ground-truth pre-filled), handoff-ladder
>   (closed-loop chain + dropped-loop status), no-fault "Shift review" framing, objective alignment,
>   and a scoring fix so self-correction is rewarded (new "Self-correction" cell) not penalised.
> - **P1 (metrics/injects):** evaluable MSEL injects (`expected_response` + `linked_objective`,
>   "N/M curveballs handled"), team MTTD/MTTR/handoff-latency + handoff-loop-closure metrics.
> - **P2:** branching injects (`twist` = adaptability, `false_lead` = discrimination decoy) with
>   honest scoring, shared-picture coherence (contested-verdict detection), live-facilitator control
>   (twist/false_lead in the instructor panel), and 6 new advanced attack stories (QuantumBank 4→7,
>   RocketStack 8→11).
> All changes were client-only except migration 0068. The items marked below are the original
> recommendations; the ✅ tags note what shipped.

### P0 — Do first (high impact, contained effort)
1. **Structured AAR + coordination timeline.** Add the four-question debrief arc and a rendered
   handoff/escalation timeline to `TeamReport`, pre-filled from the deterministic event log. *(Part 5.)*
2. **No-fault framing + error-correction credit.** Reword the report as a "shift review"; add a rubric
   signal for caught-and-reversed verdicts; stop penalising corrected early calls. *(Part 5.)*
3. **Objective alignment.** Show the assessed objectives in the lobby briefing and trace every rubric
   cell back to one. *(Part 5, Tannenbaum alignment finding.)*
4. **Verify the duration fix end-to-end.** Confirm the rebalanced feed actually streams ~20–30 min in
   a live session and the briefing matches. *(Part 3 / content audit.)*

### P1 — Next (high impact, moderate effort)
5. **Evaluable injects.** Add `expected_response` + `linked_objective` to each MSEL beat; report
   "N/5 injects handled" in the AAR. *(Part 4, HSEEP schema.)*
6. **Team-level MTTD / MTTR / handoff-loop-closure metrics** in the AAR; surface loop-closure rate.
   *(Part 6.)*
7. **Team-contextualised throughput** so backup/load-balancing scores positively; add a team credit
   for picking up an overloaded peer's case. *(Parts 2 & 6.)*
8. **Active mutual-monitoring prompt** to the Manager ("T1-X overloaded — reassign?"). *(Part 2.)*

### P2 — Ceiling-raisers (high impact, larger effort)
9. **Branching / conditional injects + a false lead** that force re-scoping and discrimination.
   *(Part 4 — highest fidelity gain.)*
10. **Shared common-operating-picture** the team co-builds; measure verdict divergence on shared
    entities. *(Part 2.)*
11. **Deepen advanced content pools** (QuantumBank/RocketStack) for hard-tier variety — this is the
    paused "4–6 advanced scenarios" task; resume on confirmation. *(Parts 7 & 8 / content audit.)*
12. **Optional human-controller override** extending InstructorPanel to fire MSEL injects / pause /
    add curveball on demand — present but not required. *(Part 4, HSEEP controller/evaluator split.)*

### Keep / strengthen (don't touch what's working)
- The **automated MSEL + pg_cron** promotion (facilitator-free tempo) — architecturally correct.
- **Deterministic seeded replay** — a rare asset; it makes the ground-truth AAR possible.
- **Content breadth** — 66 stories, 120 ATT&CK techniques, 33 event types, 24 vendors, deep noise.
- **The four-role escalation model** and the existing SituationBoard coordination surface.

### Candidates to simplify / retire
- **Any raw per-analyst leaderboard** in team context — replace with team-contextualised metrics.
- **Pressure-only injects that ask for status but change nothing** — upgrade them to evaluable and/or
  branching rather than keeping them as pure prompts.

---

## Appendix — Sources

**Frameworks & standards**
- [NIST SP 800-84 — Guide to Test, Training, and Exercise Programs (CSRC)](https://csrc.nist.gov/pubs/sp/800/84/final) ·
  [full PDF](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-84.pdf)
- [FEMA HSEEP — MSEL overview](https://preptoolkit.fema.gov/web/help/hseep-user-guides/-/knowledge_base/hseep-written-guides/msel-overview) ·
  [creating MSEL injects](https://preptoolkit.fema.gov/web/help/hseep-user-guides/-/knowledge_base/hseep-written-guides/creating-msel-events-injection) ·
  [HSEEP fact sheet](https://www.fema.gov/txt/media/factsheets/2010/hseep.txt)
- [USDA NIMS Lesson 1 — What is NIMS](https://www.usda.gov/sites/default/files/documents/NIMLesson.pdf) ·
  [NIMS Lesson 2 — Command & Management (span of control)](https://www.usda.gov/sites/default/files/documents/NIMLesson02.pdf)

**Team-performance & learning science**
- [Salas, Sims & Burke (2005) — "Is there a Big Five in Teamwork?" *Small Group Research*](https://journals.sagepub.com/doi/10.1177/1046496405277134) ·
  [overview](https://www.researchgate.net/publication/220041354_Is_there_a_Big_Five_in_Teamwork)
- [Tannenbaum & Cerasoli (2013) — "Do Team and Individual Debriefs Enhance Performance? A Meta-Analysis," *Human Factors*](https://journals.sagepub.com/doi/abs/10.1177/0018720812448394) ·
  [PubMed](https://pubmed.ncbi.nlm.nih.gov/23516804/) ·
  [practitioner guide (PDF)](https://cdn.ymaws.com/www.odnetwork.org/resource/resmgr/2013_education/tannenbaum_using_debriefs_ha.pdf)
- [Edmondson (1999) — "Psychological Safety and Learning Behavior in Work Teams," *ASQ*](https://journals.sagepub.com/doi/abs/10.2307/2666999) ·
  [AAMC interview](https://www.aamc.org/news/amy-edmondson-psychological-safety-critically-important-medicine)

**Cyber-range effectiveness & evaluation**
- [Train as you Fight: Evaluating Authentic Cybersecurity Training in Cyber Ranges (CHI '23) — TARGET taxonomy](https://dl.acm.org/doi/fullHtml/10.1145/3544548.3581046)
- [t1ger — Instructional Re-Design of a Cyber Range Exercise in a Commercial SOC (CHI '26)](https://doi.org/10.1145/3772318.3791226)
- [OffSec — Why enterprises move from generic training to cyber ranges](https://www.offsec.com/blog/enterprise-cyber-training-ranges/)

**SOC metrics**
- [CyberDefenders — SOC metrics & KPIs](https://cyberdefenders.org/blog/soc-metrics-for-analyzing-soc-performance/) ·
  [Splunk — Incident response metrics](https://www.splunk.com/en_us/blog/learn/incident-response-metrics.html) ·
  [Palo Alto — Mastering MTTR](https://www.paloaltonetworks.com/cyberpedia/mean-time-to-repair-mttr) ·
  [UnderDefense — Top SOC metrics](https://underdefense.com/blog/soc-metrics/)

---

*Cross-references: `docs/team-review/QA-2026-09-18-team-lifecycle.md`,
`INFRA-2026-09-18-team-scale.md`, `AGENT-PLAYTEST-2026-09-19-team.md`,
`CONTENT-AUDIT-2026-09-21-team.md`, `MASTER-SYNTHESIS.md`.*
