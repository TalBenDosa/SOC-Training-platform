# Test script — Team-SOC two-analyst dev run (2026-09-23)

A step-by-step manual test of every upgrade shipped today (work-division, AAR, injects/metrics,
branching, shared-picture). Run it against the **staging** dev server. Each step says **who**, **what
to do**, and **✓ what you should see**.

---

## 0. Prerequisites

- **Dev server** running on staging (`npm run dev` → http://localhost:3000). It already points at the
  staging Supabase via `.env.development.local`.
- **Logins — you need separate browser sessions per seat** (each login needs its own cookie jar):
  use separate **browser profiles**, **incognito/private windows**, or **different devices**. Same
  browser, normal tabs = same user (won't work for multi-seat).
- **Accounts:** a staging admin account creates the session; your staging demo player accounts fill
  the analyst seats. (Credentials are NOT kept in the repo — use your password manager / the
  git-ignored local env notes.)

### Recommended roster (fills every feature)
| Seat | Role | Why |
|---|---|---|
| Admin (you) | instructor (session owner) | creates the session, fires manual injects, starts/ends |
| Player 1 | **SOC Manager** (`mgr`) | Situation Board, overload **Nudge**, SITREP, AAR |
| Player 2 | **Tier-1** | analyst A (overload target) |
| Player 3 | **Tier-1** | analyst B (does the backup / take-over) |
| Player 4 | **Tier-2** | acknowledges → handoff ladder, containment, re-scope |

> **Short on accounts?** Minimum viable = **2× Tier-1** (covers Take-next, orphan badge,
> take-over/backup). Add the **Manager** seat to test the nudge; add **Tier-2** to see the full AAR
> (handoff ladder, MTTR, curveballs). One person can open 4 profiles and drive all seats.

### Setup
1. **Admin:** open http://localhost:3000/team → *New team exercise* → Company **QuantumBank** (or any),
   Difficulty **Medium** (medium/hard enable the MSEL injects), tick your players and set each role per
   the table → **Create & open lobby**.
2. **Each player:** log in (own profile), open `/team`, click the live session, **Ready up**.
3. **Admin/Manager:** start the shift. Feed begins streaming.

---

## Part A — Active work-division (the core "two analyst" test)

### A1. "Take next" assisted pull  ·  Tier-1
- **T1-A:** in the **Alert queue** card, click **Take next**.
- ✓ The most urgent un-claimed alert opens its report and is **claimed by you** ("✓ you claimed this
  alert"). Repeat — it never hands you an alert already locked by someone else.

### A2. Overload + Manager nudge + rebalance banner  ·  needs 2×T1 + Manager
- **T1-A:** open **3+** high/critical alerts from the queue (each open auto-claims it); **don't**
  disposition them — leave them open so your load ≥ 3.
- **Manager:** watch the **Situation Board → "Team & load"** — T1-A shows **`3 open`** (amber). A
  **"Rebalance load"** card appears with T1-A listed.
- **Manager:** click **Nudge** next to T1-A.
- ✓ **Every player** sees a banner near the top: *"[Manager] asks the team to rebalance — [T1-A] is
  overloaded (3 open). If you're light, take the next case."*
- **T1-B:** click **Take next** (or select one of T1-A's alerts → **Take over**).
- ✓ Load rebalances; when T1-A drops below 3, the "Rebalance load" card / banner clears.

### A3. Orphan-item badge  ·  Tier-1
- Let a **high/critical** alert sit in the queue **unclaimed** past its SLA (critical ≈1 min, high
  ≈3 min) — nobody opens or escalates it.
- ✓ It gets a red **⚠ unclaimed** tag and **jumps to the top** of the queue.

### A4. Span-of-control (optional)  ·  Manager
- With **>7** analysts online, the Situation Board **"Online"** metric turns amber and a note appears
  ("beyond a ~7 span of control…"). Skip if you don't have 8 seats.

---

## Part B — Curveballs & branching (MSEL)

On medium/hard the injects auto-fire over the shift; you can also fire them on demand:
- **Admin (instructor):** in the **Instructor view → Inject**, the kind dropdown now includes
  **plot twist (forces a re-scope)** and **false lead (a decoy to reject)**. Fire each.

### B1. Twist (adaptability)
- When a **twist** inject appears ("…host is beaconing to a NEW C2 — re-scope"):
- **T2/T3:** react — set a new **scope** / re-open the case (or a T1 re-escalates) within ~15 min.
- ✓ This will show as **handled** in the AAR curveballs list.

### B2. False lead (discrimination)
- When the **false lead** inject appears ("Marketing's sanctioned SaaS tool looks like exfil…"):
- **Team:** recognise it's benign — **do not** escalate/contain it.
- ✓ In the AAR it's tagged **decoy** ("did the team correctly reject it?").

### B3. Management pressure / help-desk (from P1)
- **Manager:** answer a **management-pressure** inject by sending a **SITREP** (Manager console).
- **T1:** answer a **help-desk ticket** inject (Handle button).
- ✓ Both count toward "N/M curveballs handled" in the AAR.

---

## Part C — Coordination chain, corrections, then the AAR

### C1. Build a handoff chain (for the ladder + MTTR)
- **T1:** escalate a **real attack** log (🚩 with evidence). **T2:** **Acknowledge** it → investigate →
  **request containment**. **Manager:** **approve**. **T2:** **execute** isolation → **resolve**.
- Also: **T1** escalate one thing that **nobody acknowledges** (leave it) — this becomes a **dropped**
  chain.

### C2. Self-correction (no-fault scoring)
- **T1:** disposition a **real attack** wrongly as **benign**, then re-open it and set **true positive**.
- ✓ In the AAR your **Disposition accuracy** is **not** dropped by the wrong first call, and a
  **"Self-correction"** cell appears.

### C3. Contested call (shared picture)
- **T1-A** and **T1-B:** disposition the **same** event with **opposite** verdicts (one *true
  positive*, one *benign*).
- ✓ AAR flags it under **"Contested calls — reconcile the picture"**.

### C4. End the shift → open the After-action report
**Manager/Admin:** End the session, then open the report. Verify:
- **Header** reads **"Shift review"** with the no-fault line.
- **Metrics grid:** **MTTD**, **MTTR**, **Handoff latency**, **Handoff loop closure**, **Shared
  picture** (aligned / N contested).
- **Hot-wash:** the **4-question debrief arc** — steps 1–2 pre-filled with real facts (attack count,
  detect/contain times), steps 3–4 open for discussion.
- **Handoff chains card:** each escalated case as a ladder with per-hop latency and a **closed /
  open / DROPPED** badge (the un-acked one from C1 = **dropped**).
- **Contested calls card:** the C3 event with both conflicting verdicts + names.
- **Curveballs (MSEL) card:** **N/M handled**, with **handled / missed / decoy / FYI** badges.
- **Per-analyst rubric cards:** T1-B shows a scored **"Backup & load-balancing"** cell; the
  self-corrector shows **"Self-correction"**; the Manager shows **"Load balancing"**.

---

## Quick smoke path (if you only have 2 logins, both Tier-1)
Take next (A1) → overload one T1 by opening 3 alerts → other T1 **Take over** one (A2 without the
nudge) → let a high alert go orphan (A3) → both disposition one event oppositely (C3) → one corrects a
verdict (C2) → end shift → check the AAR header, Shared-picture metric, Contested card, and the
Backup/Self-correction rubric cells.

---

## Notes
- Everything here runs on **staging**; nothing touches prod.
- If a login hangs, it's the known staging-auth flakiness from some networks — retry, or use a
  different profile/device.
- Report anything that doesn't match a **✓** and I'll fix it.
