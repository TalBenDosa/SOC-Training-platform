# Analyst Performance Telemetry — Measurement Plan

**Why this matters:** the Front-A research verified that **per-action activity tracking during an investigation** (not just the final answer) is exactly what separates a serious platform (LetsDefend) from a quiz app — and it's the single most concrete, buildable differentiator we found. It also matches NIST NICE's framing of a **Skill** as "the learner's *observable action*," and every real SOC measures its analysts the same way (MTTD, MTTR, escalation accuracy, false-positive rate) — not "did they eventually get it right."

**What we already capture today (verified in code):** exactly one behavioral metric — `avgCatchMs` in the Dashboard (time from attack injection to a correct classification). Rooms/TaskPlayer capture **zero** timing or process data — `onComplete(xpEarned: number)` is the entire signal. This plan is a from-near-zero build.

---

## 1. Metric taxonomy — what to measure and why

### A. Speed / latency (the "how long" the user asked about)
| Metric | What it captures | Where |
|---|---|---|
| **Time-to-first-action** | How long before the student even opens the first log row / starts reading | Rooms, Dashboard |
| **Decision latency** | Time from "task/event shown" to "answer submitted" | Every gradeable task type |
| **Time-to-correct-verdict (MTTD analogue)** | Time from attack injection to the *first correct* classification — already exists as `avgCatchMs`, extend per-event not just per-session | Dashboard |
| **Report-writing duration** | Time from opening the Incident Report modal to submit | Dashboard |
| **Time-to-escalate** | For analyst_choice tasks with an "escalate" option — how long before that decision | Rooms, Dashboard |
| **Session pacing** | Total active time vs idle time; time distribution across task types (reading vs log_analysis vs question) | Rooms |

### B. Accuracy / quality (speed is meaningless without this — see guardrails)
| Metric | What it captures |
|---|---|
| Correct-verdict rate | Per task-type, per room, per MITRE technique, per vendor/log-source |
| **False-positive rate** vs **false-negative (missed-attack) rate**, tracked *separately* | A student who over-escalates everything and one who misses real attacks have opposite, equally-wrong profiles — averaging them hides both |
| IOC-identification accuracy | Real IOCs found vs fabricated ones claimed (the incident-report grader already checks this — surface it as a trend, not just pass/fail) |
| Report rubric sub-scores over time | Impact / root cause / containment / evidence-citation — track each dimension's trend, not just the composite score |

### C. Investigation *process* (the real differentiator — this is what LetsDefend "tracks every activity" means)
| Metric | What it captures |
|---|---|
| **Events opened before deciding** | Thoroughness — did they check 2 events or 20 before committing to a verdict? |
| **Pivot behavior** | Did they follow an IOC (IP/hash/user) from one event to related events, or investigate each event in isolation? |
| **Revisit rate** | Did they go back to re-read an earlier event after seeing a later one? (Good sign — updating a hypothesis with new evidence) |
| **Order of field access** (log_analysis tasks) | Did they check the fields that actually matter first, or scroll randomly? A cheap proxy: did they open the field the question ultimately depends on before or after other fields? |
| **Change-of-mind rate** | Selected one MCQ/verdict option, then changed it before submitting — signals genuine deliberation vs guessing |
| **Confidence calibration** | *(new mechanic, flagged in the earlier engagement research)* — ask "how confident?" before reveal; compare stated confidence to actual correctness. A well-calibrated analyst who says "low confidence" and is right less often than "high confidence" is a stronger signal of self-awareness than raw accuracy alone |

### D. Trend / mastery over time
| Metric | What it captures |
|---|---|
| Per-technique / per-source accuracy trend | Already partially computed on the Progress page — extend to feed **adaptive difficulty** (a roadmap item already identified) |
| Retry-to-pass count | How many attempts a room took at the 65% gate — a room that consistently takes 3+ retries across many students is a content signal, not just a learner signal |
| Skill decay | Accuracy on a previously-mastered technique after N days without practice — supports spaced-repetition scheduling |
| Improvement slope | Is decision latency *decreasing* while accuracy stays flat/improves? That's the real "becoming an analyst" signal — faster AND still correct |

---

## 2. Critical design guardrails (do these before shipping any of it)

1. **Never reward speed alone.** A fast wrong verdict must never score better than a slow correct one. Every speed metric is a *secondary* axis reported *alongside* accuracy, never a substitute for it — otherwise the platform teaches guessing.
2. **Don't punish careful, correct investigation.** A student who opens 15 events, follows 3 pivots, and gets the *right* answer should never look worse than one who guessed the first event correctly in 4 seconds. Frame thoroughness-when-uncertain as neutral-to-positive, not as a penalty.
3. **Track false-positive and false-negative rates separately, always.** Never collapse them into one "accuracy" number — a SOC that over-escalates burns the business; one that misses attacks is the actual product failure. These are different skills with different remediation.
4. **This is process telemetry for *learning*, not surveillance.** Store per-session, local-first (matches the current localStorage architecture), and never surface raw click-streams to anyone but the learner themselves and, later, an aggregate/anonymized content-quality signal for the content-validator agents. No "this student took too long" shaming UI.
5. **Apply the LLM-as-judge bias lessons to any AI-graded process metric too.** If an LLM ever scores *investigation quality* (not just the final report), the same position/verbosity/self-preference biases from the Front-C research apply — randomize any ordering shown to a judge model, and don't let verbosity of a written justification substitute for correctness.
6. **Every metric should map back to a NICE Skill statement** where possible ("triage an alert," "identify an IOC," "recommend containment") — this keeps the measurement suite tied to real competency, not vanity stats.

---

## 3. Instrumentation architecture (buildable on the current stack)

No backend exists today (localStorage-only) — this plan works within that constraint and upgrades cleanly if a backend is added later (per the product roadmap's "big bet" #1).

1. **A shared `useTaskTelemetry` hook** (new, small) wrapping task lifecycle: records `shownAt` (mount time), `firstInteractionAt`, `submittedAt`, and an `events: {type, payload, ts}[]` micro-log (event opened, field clicked, option changed, IOC tagged). One hook, reused by `TaskPlayer` (Rooms) and `EventFeed`/`IncidentReportModal` (Dashboard) — avoids duplicating timing logic per task type.
2. **Extend `RoomProgressEntry`** (RoomClient.tsx) with an optional `telemetry: TaskTelemetry[]` array alongside the existing `completedTaskIds`/`xpEarned` — additive, doesn't touch the pass/fail logic already shipped.
3. **Extend `DashboardSessionRecord`** (useLiveEvents.ts) — `avgCatchMs` already exists; add `perEventOpenOrder`, `pivotCount`, `reportDraftRevisions` (the report modal already autosaves drafts — count the diffs), `escalationLatencyMs`.
4. **A `soc-analyst-metrics` view** (new, small addition to Progress page) surfacing 2-3 of the most legible trends first (accuracy-over-time, FP-vs-FN split, decision-latency trend) rather than dumping every raw metric — avoid overwhelming the learner with data they can't act on.
5. **Feed into the existing "adaptive difficulty" roadmap item**: per-technique accuracy + decision-latency together are exactly the signal needed to route the *next* event toward a learner's weak spot, which was already flagged as a high-value, medium-effort roadmap move.

---

## 4. Phasing (buildable in order, each phase independently useful)

1. **Phase 1 (cheap, high value):** decision latency + correct/incorrect per task, FP/FN split, events-opened-before-deciding. Pure client-side timestamp math, no new UI required beyond a Progress-page trend chart.
2. **Phase 2:** pivot/revisit tracking (requires tagging IOC-click and row-reopen events already partially present in `EventFeed`'s IOC-tagging notebook — extend it to log, not just store, the interaction).
3. **Phase 3:** confidence-calibration mechanic (new UI: a confidence prompt before reveal) — ties to the engagement-research recommendation already in the roadmap.
4. **Phase 4:** feed accumulated per-technique accuracy + latency into adaptive next-event selection (the roadmap's "AI tutor that hunts blind spots" idea).

This plan intentionally stops short of writing code — say the word and I'll implement Phase 1 first (it's the cheapest and most directly useful), verify with `tsc` + the browser as usual.
