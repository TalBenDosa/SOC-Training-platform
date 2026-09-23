# Changelog — Team-SOC upgrades (2026-09-23)

Research-driven upgrade of the **Team-SOC ("HACK THE SOC") multiplayer** exercise, taking it from a
working feature to an evidence-based team-training instrument. Grounded in
[`RESEARCH-2026-09-23-team-training-design.md`](RESEARCH-2026-09-23-team-training-design.md) and
[`SPEC-team-role-division.md`](SPEC-team-role-division.md); prior audits in the same folder.

> **Scope & safety:** everything here is **staging-only**. Nothing was deployed to prod / `main`.
> All changes are **client-only over the existing event log** except **one migration (0068)**. All
> new scoring is **log-derived and deterministic** (a seeded replay reproduces the exact debrief), and
> **honest** — new rubric cells are null-when-absent (excluded from the %), never negative.

---

## 1. Active work-division / load-balancing
*Turned the passive "collision-avoidance" model into active mutual-monitoring + backup (Salas Big Five).*

- **Overload nudge (`coordination.nudge`)** — the SOC Manager's Situation Board flags online analysts
  carrying ≥3 open cases (T1 soft-claims + T2/T3 acked cases) and offers a **Nudge**; the whole team
  sees a rebalance banner. New scored event → **migration `0068_team_coordination_nudge.sql`**
  (mgr/lead, running; deny-by-default preserved). Applied to staging, gate verified.
- **Backup & load-balancing rubric cell** (T1/T2) — credits a *Take-over* of a teammate's alert, or
  acking a case while a **same-role** peer is overloaded. Manager gets a **Load balancing** cell
  scoring *coverage of overload episodes by nudges* (not raw nudge count → no spam incentive).
- **"Take next" assisted pull** — one click grabs the most urgent unclaimed alert (T1) / case (T2).
- **Span-of-control guard** — warns when a Manager coordinates >7 online analysts (NIMS/ICS 3–7).
- **Orphan-item badge** — a past-SLA, unclaimed, un-escalated high/critical sorts to the top of the
  T1 queue with a **⚠ unclaimed** tag.

## 2. AAR upgrade (P0) — the highest-ROI component
*A structured, no-fault, ground-truth debrief (Tannenbaum: structured debriefs ≈ +25%; Edmondson: reward error-correction).*

- **Structured 4-question debrief arc** — *What should have happened · What actually happened · Why the
  gap · What we'd do differently*; the first two are pre-filled from ground truth (attack count,
  detect/TTD/contain facts).
- **Handoff ladder** — per-case closed-loop chain (T1 escalate → T2 ack → T3 → contain → resolve) with
  per-hop latency and a **closed / open / DROPPED** status (escalated-but-never-acknowledged = a broken
  loop, surfaced first).
- **No-fault "Shift review" framing** + lobby objective alignment (the 3 briefed objectives map to the
  3 scored rubric dimensions: accuracy · timeliness · coordination).
- **🐛 Scoring fix — self-correction no longer penalised.** Disposition accuracy (per-user **and**
  team) now scores over *distinct events keeping the latest verdict*; a wrong→right correction scored
  50% before, now 100%. New **"Self-correction"** cell rewards catching your own mistake.

## 3. Metrics & evaluable injects (P1)
- **Evaluable MSEL injects** — each scripted inject carries `expected_response` + `linked_objective`;
  the AAR pairs it to the team's response (SITREP / ticket-answer) in a 15-min window and reports
  **"N/M curveballs handled."**
- **Team coordination metrics in the AAR** — **MTTD**, **MTTR** (escalate→resolve), **Handoff latency**
  (escalate→first-ack, team MTTA), and **Handoff loop closure** (% of escalations acknowledged).

## 4. Branching injects & shared picture (P2)
- **Branching injects** (adaptability + discrimination), atop the existing deterministic MSEL:
  - **`twist`** — "the host is beaconing to a *new* C2 — re-scope"; scored *handled* if a re-scope
    action (scope.set/confirm, case status, fresh escalation) follows within 15 min.
  - **`false_lead`** — a sanctioned-tool decoy; shown as a **decoy** to reflect on (honest: not
    fake-scored on restraint we can't attribute).
- **Shared-picture coherence** — detects **contested calls** (same event, two analysts, opposite
  verdict class); AAR shows a "Shared picture: aligned / N contested" metric + a reconcile card.
- **Live-facilitator control** — `twist` / `false_lead` added to the Instructor panel's inject
  composer (the MSEL fires them automatically when no instructor is driving).

## 5. Content — deeper hard tier
- **6 new `advanced` attack stories** closing the content-audit gap (hard tier was thin):
  - **QuantumBank:** SWIFT wire-fraud · fraud-monitoring tampering · CyberArk PAM → money-mule.
  - **RocketStack:** CI/CD pipeline poisoning · Terraform IaC backdoor · SaaS OAuth consent-chaining.
  - Real per-vendor telemetry (Okta, CyberArk, AWS CloudTrail/GuardDuty, GitHub, Zscaler, Palo Alto,
    FortiGate, CrowdStrike), coherent MITRE kill-chains, tenant-pure.
  - Candidate pools: **QuantumBank-hard 4→7**, **RocketStack-hard 8→11**.

---

## Files changed
| File | Change |
|---|---|
| `src/app/(app)/team/[id]/page.tsx` | overload nudge + backup/self-correction/load-balancing scoring, Take-next, span-of-control, orphan badge, handoff ladder, 4-question arc, no-fault framing, MTTD/MTTR/loop-closure/shared-picture metrics, evaluable/branching injects, contested-calls & curveballs cards, instructor inject kinds |
| `src/lib/team/buildTimeline.ts` | `expected_response`/`linked_objective` on every inject; `twist` + `false_lead` beats |
| `src/app/(app)/dashboard/attackStories.ts` | 6 advanced QuantumBank/RocketStack stories (+ `vcs` source alias) |
| `supabase/migrations/0068_team_coordination_nudge.sql` | whitelist `coordination.nudge` (mgr/lead, running); **applied to staging** |

## Verification
- **Gates — all green:** `tsc --noEmit` · `vitest` 157/157 · `npm run build` ·
  `validate:content` (0 errors) · `validate:feed` · `validate:logs` ·
  `validate:scenarios:integrity` (0/0) · rooms-meta (no drift).
- **Migration 0068** applied to staging; gate checks pass
  (`coordination.nudge`(mgr)=t, (t1)=f, bogus=f).
- **Scoring proven** via synthetic replication: self-correction wrong→right = 100% + 1 correction (was
  50%); regression right→wrong = 0% (no undeserved credit); `twist`+re-scope = handled; `false_lead` =
  decoy/unscored; contested-verdict detection flags only genuine splits.
- **Content spot-reviewed** for MITRE + vendor-field fidelity and tenant purity.
- **Not done:** live end-to-end multi-user playthrough — staging Supabase auth is unreliable from the
  sandbox; recommend a 2-analyst dev run to view the ladder/curveballs/contested cards in the UI.

## Not yet in prod
Feature branch remains staging-only and unpushed; no Team-SOC work is in production. Deploy requires
explicit authorization.
