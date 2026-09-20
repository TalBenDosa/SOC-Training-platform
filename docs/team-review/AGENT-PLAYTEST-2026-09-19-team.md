# Team-SOC — Role-Agent Playtest (2026-09-19)

Four role-persona agents each role-played a full shift through the Team-SOC implementation from their
seat, then answered a follow-up round. Each judged the feature on **role fit · UX · collaboration ·
professional depth** (1–5) with file:line evidence, and answered "does this seat match the real role?"

- **Tier-1 (Maya)** — alert triage / disposition / escalate-with-evidence
- **Tier-2 (Daniel)** — investigate, EDR, scope, incident report, containment, elevate
- **Tier-3 (Priya)** — elevation hunt queue, hypothesis-driven hunting, scope confirmation, mentoring
- **SOC Manager (Marcus)** — queue oversight, containment approval, decision log, SITREPs, command

*Method:* static/code-based role-play (a live multi-user run isn't possible from the dev sandbox).
Evidence is `page.tsx` = `src/app/(app)/team/[id]/page.tsx`.

## Scorecard

| Role | Role fit | UX | Collaboration | Prof. depth | One-line verdict |
|---|---|---|---|---|---|
| **Tier-1** | 4 | 4 | 4 | 3 | Excellent evidence-driven *handoff*; missing the alert queue/SLA that *defines* a T1 shift. |
| **Tier-2** | 4 | 3.5 | 4 | 4 | Most role-authentic analyst seat; two headline promises leak (dead intel button, write-only report). |
| **Tier-3** | 3 | 3 | 2 | 2 | Role-shaped UI, but shallow count-rewarded hunting disconnected from the great EDR console; bare-button handoff. |
| **SOC Manager** | 4 | 3 | 3 | 4 | Most conceptually real coordinator seat (correct no-raw-feed boundary); commands half-blind; 2 mechanics break solo. |

## What's genuinely good (keep)

- **T1→T2 handoff.** Forced disposition + 12-word rationale + analyst-selected IOCs (not auto-seeded) + the
  **full raw log snapshot** riding with the escalation, and a real bounce-with-reason loop. Better than many
  production SOCs. (T1 & T2 both praised.)
- **The EDR console** (`src/components/edr/EdrConsole.tsx`) — process ancestry, real hash DB, stateful RTR
  shell, network chain, timeline, verdict grading that accepts *any* hash-confirmed-malicious process. The
  standout surface; all three analyst roles rated it the most realistic tool.
- **Separation of duties & boundaries.** T2 *requests* containment, the Manager *approves* (with a required
  rationale, deny-gated). Coordinators are correctly kept **out of the raw feed** (Situation Board only).
- **Honest scoring discipline.** Un-instrumented rubric cells score `null` and are excluded from the %;
  the management-pressure↔SITREP metric is paired one-to-one within a 15-min window (not gameable by one
  late SITREP).
- **Session lifecycle & prioritization** — SLA-by-severity inbox, prioritized queue, claim-on-ack lock,
  queue-oversight for the Manager.

## Cross-cutting themes (the story across all four seats)

1. **Handoffs are the weak seam — and handoffs are the whole point of a *team* trainer.** T1→T2 is strong,
   but everything downstream thins out:
   - **T2's incident report is write-only.** `report.submitted` feeds only the end-of-exercise rubric; it is
     never rendered in the Shared Case or shown to T3/Manager live — yet the card claims "This is the handover
     Tier-3 and the SOC Manager read" (`page.tsx:1491`). *Daniel: "a handover no downstream teammate reads is
     not a handover — fixing it is a prerequisite for the feature to meet its own goal."*
   - **The containment request carries only `target` + `reason`** (`page.tsx:1430`) — the Manager approves
     **blind** to the scope and recommendation the hard-gate just forced T2 to write.
   - **T2→T3 elevation is a bare button** (`page.tsx:1432-1434`) with no "what to hunt / why elevating" and
     none of T2's findings — so T3 restarts the case from the original alert. *Priya's #1 required fix.*

2. **Depth is uneven — a great tool next to shallow form-filling.** The EDR console is deep; but the
   **threat-intel enrichment button is dead** (`onThreatQuery={() => {}}`, `page.tsx:1397/1923`) — a mandated
   investigation channel the spec marks built — and the **hunt log is count-rewarded** (8-char hypothesis,
   `finding` never scored; "Hunt yield" = raw count, `page.tsx:2220`).

3. **Role fit is good but leaks at the edges.**
   - **T1 has no alert queue** — an endless chronological stream, no un-triaged count, no per-alert aging.
     "Keep the queue clean" (briefing) with no queue. SLA logic exists but T2-only.
   - **Full T2 controls leak into the T3 seat** — a hunter can ack/**bounce** raw T1 escalations and file a
     T2 report (`page.tsx:808/1435`), training "senior = does everyone's job."
   - **Manager commands half-blind** — the Situation Board shows log volume, not team state (no presence,
     no per-analyst load, no live SLA); *"I know the tickets, I don't know the people."*
   - **Two mechanics break in an instructor-less session** (a supported mode): `mgmt_pressure` is
     instructor-only, and the Manager sees **only their own** after-action card (`page.tsx:2530`).

4. **Scoring is gameable in several places** (form over substance): the IOC gate accepts junk free text
   (`detectIocType` falls back to `host`); `reportQualityScore` is word-count + a loose `\w+\.\w+` regex;
   hunt "yield" is a count; technique attribution accepts any non-empty string; **escalation precision is
   scored by whether T2 acked** (not ground truth) — unfair when no/slow T2, and it *rewards* a T2 acking a
   bad escalation.

5. **Manager decisions lack the data they're graded on.** Containment approval asks for "business impact"
   with **no asset-criticality / business-owner / blast-radius data** on the card — so the seat's defining
   action is a rubber stamp; and coordination is **invisible to scoring** (no first-class "tasked X to do Y"
   directive — chat is ephemeral and unscored).

## "Does it match the role?" — per-seat verdict

- **Tier-1:** Yes for *evidence-driven escalation* (the handoff is the best-taught skill in the sim). No for
  *queue discipline* — the seat never presents a prioritized, aging worklist, so it trains report-writing but
  not the triage-under-SLA that defines a T1 shift.
- **Tier-2:** The most role-authentic analyst seat — inbox → investigate (EDR) → scope → determination →
  request containment → elevate, with correct separation of duties. But two headline promises leak (dead
  intel button; the "orderly handover" is write-only), so it *nearly* matches the role.
- **Tier-3:** Role-*shaped* but not yet a hunter's seat. The bones are right (elevation queue, scope-confirm,
  EDR), but the hunt itself is shallow count-rewarded form-filling disconnected from the deep tool beside it,
  the handoff in both directions is a bare button, and T2 line-work leaks in.
- **SOC Manager:** The most conceptually real coordinator seat — containment authority, gated
  decisions/SITREPs, honest pressure↔SITREP metric, correct no-raw-feed boundary. But it commands
  half-blind (environment, not team) and two flagship mechanics quietly break solo.

---

## Prioritized roadmap

### A. Launch-blockers — fix before a real cohort uses it
These either void the scorecard's credibility on day one or defeat the feature's core purpose.

1. **Make the incident report a live handover** *(T2, core-purpose)* — render the latest `report.submitted`
   inside `SharedCase`, and include `{scope, recommendation, verdict}` in the `containment.requested` payload
   so the Manager approves *with* T2's justification. (Daniel: prerequisite for the feature's own goal.)
2. **Enrich the T2→T3 elevation** *(T3, required)* — add a required "what to hunt / why elevating" field to
   `elevation.requested` and surface T2's filed findings in the elevation card. (Priya's #1; unblocks hunt quality.)
3. **Wire the threat-intel enrichment** *(T2/T3)* — render `ThreatIntelDrawer` and pass a real `onThreatQuery`
   (mirror `EventFeed.tsx`); ~10 lines. A dead "check this hash" button teaches the wrong lesson.
4. **Fix scoring that unfairly/independently breaks:**
   - Escalation precision scored vs **ground truth at the debrief** (add recall); relabel T2-ack as a separate
     "coordination/handoff" signal. *(T1 launch-blocker.)*
   - IOC gate: reject type-invalid junk (don't count it toward the ≥1-IOC gate); keep external-intel allowed.
   - Restrict escalate to `true_positive`/`suspicious` dispositions (no escalating a benign-marked log).
5. **Un-break instructor-less sessions** *(Manager)* — auto-schedule 3–4 `mgmt_pressure` injects from the
   scenario timeline; let `role === "mgr"` see the whole-team AAR (not just their own card).

### B. Next iteration — high value, not blockers
6. **T1 alert-queue strip** — a filtered/sorted projection over the existing feed (Age · Sev · Source · desc,
   sorted by severity×age, un-triaged count, reuse `prioKey`/`slaMinFor`). ~a `useMemo`; not a second SIEM.
7. **Per-incident scope** — key `ScopeState` by `event_id`; today one global scope unlocks containment on
   every open case (anti-teaching the moment a second ticket exists — which the platform is built to create).
8. **Embed the EDR console as a drawer for team play** (`EdrConsole` already supports `embedded`) — the new
   tab has multiplayer failures: pop-up-blocked is silent mid-shift, `localStorage` handoff is last-write-wins
   (T2 & T3 clobber each other's investigation), and the analyst leaves the shared session view.
9. **Real `huntQualityScore`** (deterministic, replaces count) — hypothesis substance w/ a cited case entity
   (25) · cited evidence: pinned event_id / EDR verdict (35) · validated `T####` in-case (25) · conclusion
   verdict confirmed/refuted/inconclusive (15); band `bandHigh(avg, 75, 55, 30)`.
10. **Business-impact on containment approval** *(Manager's #1)* — 3 chips from the request payload: asset
    criticality tier · "what breaks if isolated" · business owner/hours. Converts rubber stamp → real risk call.
11. **Manager command dashboard** — per-analyst live load + presence + oldest-unacked-per-tier + live MTTA on
    the Situation Board (command from awareness, not from waiting for a request).
12. **Gate T3 out of raw-queue work** — remove ack/**bounce** of T1 escalations and the T2 report card from the
    T3 seat; keep a read-only queue peek + containment recommendation; make the hunt log the primary artifact;
    render `HuntConsole` above the inbox.

### C. Later / polish
13. First-class **"tasked X to do Y" directive** event so Manager coordination is visible & scored (not a full
    work-router — that's scope creep).
14. Carry the **EDR verdict back** into the hunt-log draft; a **retro-hunt/saved-query-with-match-count**
    primitive for T3 (DE already has the engine).
15. `reportQualityScore` substance (validate IOCs against the case, not a shape regex); validate technique
    `T####`; raise confirmed-scope cap 8→12.
16. UX tidy: one canonical escalate path (drop the redundant dropdown / dedupe the 2–3 "Investigate in EDR"
    buttons); "hide dispositioned" toggle; fix the `ROLE_GUIDE.t1` step that tells T1 to pin (T1 has no pin).

## Bottom line
Structurally sound with two genuinely strong pillars — the **T1→T2 evidence handoff** and the **EDR
console**. It is a credible foundation. But it does **not yet fully deliver its core multiplayer promise**
(tier-to-tier handover) because T2's report is write-only, T2→T3 is a bare button, and the Manager approves
blind. Close the handoff gaps (A1–A2), wire the dead intel channel (A3), fix the day-one scoring unfairness
(A4), and un-break solo sessions (A5), and the feature graduates from "role-shaped UI" to a team trainer a
real SOC would respect.
