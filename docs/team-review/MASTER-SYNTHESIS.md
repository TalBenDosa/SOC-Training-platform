# Team-SOC Exercise — Multi-Agent Review Synthesis

**Date:** 2026-09-16 · **Session driven:** `05e9c820-dcd0-42b3-8d1f-544609681a7f` (2×T1 · 2×T2 · T3 · SOC Manager · instructor)
**Method:** dummy full-team run-through + 5 specialized AI reviewers observing from the side (report-only). Individual reports: `00-infra-health.md`, `01-ux-ui.md`, `02-experience-method.md`, `03-realism.md`, `04-content-fidelity.md`.

## Headline
Mechanics are strong (**realism 4/5**, all gates green, onboarding works without a facilitator). The gaps are **not architectural** — every finding is a scoped, file-level fix. Two themes dominate: (1) the **method is static** (one incident, no tempo, no guided debrief), and (2) a handful of **integrity leaks** (RBAC half-enforced, "no-hints" copy, split identity) that must close before a real cohort plays.

---

## Cross-agent convergence (flagged by ≥2 reviewers → highest confidence)

| Finding | Agents | Severity |
|---|---|---|
| **Server RBAC enforces only ~9/25 action types**; `containment.executed`, `staff.inject`, `rule.published` etc. fall through to open default | realism, infra, experience | 🔴 P0 |
| **`staff.inject` role mismatch** — `InstructorPanel` renders on `me.is_staff` but the DB gate requires `role='instructor'` → a 2nd admin/instructor playing a tier gets a dead "Send inject" button | infra, experience, realism | 🔴 P0 |
| **🚩 escalate skips claim/soft-lock + disposition** → two T1s can double-escalate the same log; disposition-accuracy metric bypassed | ux-ui, experience | 🔴 P0 (my new feature) |
| **Single incident drains to whole team** → dead time for T3/Manager, redundant work for multi-T1/T2 | experience, realism | 🟠 P1 |
| **No guided AAR / replay** ("who knew what when") — all data already in the event log, only a view layer missing (≈3× learning) | experience, realism | 🟠 P1 |

---

## P0 — fix before the next real run (bugs & integrity)

1. **Complete the `session_action_allowed` gate** (realism/infra) — add the ~16 ungated action types with correct role×status. One SQL migration. *Security + realism core.*
2. **Fix `staff.inject` authority** (infra `page.tsx:490` vs `0060:38`) — align the render condition and the DB gate (staff OR instructor) so inject works for whoever the product intends.
3. **🚩 flow: auto-claim + require disposition** (ux-ui) — flagging a log should take the soft-claim and set/require a disposition inside the report flow, so the shortcut doesn't bypass T1's two core mechanics.
4. **Kill the "no-hints" copy leaks** (ux-ui) — the help-desk **"Reject (vishing)"** button names the technique; the TI decoy prints **"likely a bad IOC"** pre-verification. Reword both.
5. **Normalize the split identity** (content) — NexaCorp IT admin is `it-admin` in AD/DC (67×) vs `it.admin` in EDR decoys (37×); T2 pivot/scope breaks across the seam. Normalize to `it.admin` everywhere.

## P1 — significant experience/realism lift

6. **Second incident (decoy + real)** so multi-T1/T2 have parallel load and T3/Manager aren't idle.
7. **Guided AAR / timeline replay** at End-Exercise (dual-track "who saw/did what when" + key moments) — data already exists in `session_events`.
8. **Tempo without a facilitator** — auto-MSEL injects and/or a light cadence signal (the removed SLA/nudge were too heavy; a subtler tempo cue is the middle ground).
9. **Routed escalations** — assign an escalation to a specific T2 (or claim-in-inbox) so multi-T2 don't duplicate; give T3 a dedicated elevation, not only end-of-chain work.
10. **Quality gate on Decision-log & SITREP** (realism) — mirror T1's gate so Manager output isn't one-liners.
11. **Firewall field fidelity** (content) — `nx_d4` mixes invented `pan.threat_id`/`pan.app` with canonical `panw.threatid`; consolidate to one real PAN-OS schema.
12. **Feed triage state** (ux-ui) — show what's already claimed/dispositioned/escalated so the shared feed doesn't cause collisions at realistic size.

## P2 — polish & robustness

13. **Single-seat disconnect → reassign** (experience) — T3/Manager drop currently stalls the relay; allow the instructor to reassign the seat.
14. **Silent-failure handling** — when nobody escalates the real attack, surface it in the debrief instead of nothing happening.
15. **T3 always-open card stack** (ux-ui) — the doc claims this was tabbed; it isn't. Collapse to the secondary-panel pattern.
16. **DetailPanel-in-`<td>` nesting** (infra) — T2's "Open the flagged log" renders a `<td>`-rooted DetailPanel inside a `<div>`; React dev warning + `display:table-cell` risk. Wrap in a minimal table or refactor DetailPanel's root.
17. **`duplicate key … session_events_seq`** — transient seq race (pg_cron vs concurrent write); add retry-on-seq-conflict in `apply_session_action`.
18. **Dead rubric hooks** — `evidence.pinned`/`rule.tuned` are gated & scored but no UI fires them; wire buttons or drop from the rubric.

## Not covered (needs a live/staging pass)
No browser-automation run by the agents; no check that migrations 0049–0060 are actually applied on staging or that pg_cron is live; no concurrency test of the soft-claim / optimistic-seq path. (I verified the relay + gates live in-browser separately.)

## What's strong (keep)
Shared real-time feed; role-gated state machine; T1 structured report with a real quality gate + full-log snapshot; MITRE-format decision-log/SITREP; full reuse of the single-player engines (EDR, 49 ATT&CK scenario-packs, continuous background noise); solo onboarding (directive banner + RoleGuideModal + consistent DetailPanel); snapshot→T2 path preserves all fields; **no regression to the single-player dashboard** (new EventFeed props all optional/unused there).
