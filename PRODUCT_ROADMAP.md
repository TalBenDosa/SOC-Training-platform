# SOC Training Platform — Product Brief & Roadmap

**Role:** Product Manager brief. **Mission of the product:** take a learner from **zero knowledge** (doesn't know what an IP is) to a **SOC analyst who investigates real incidents and writes an incident report**.
**Date:** 2026-07-04. **Method:** 6 parallel specialist assessments (pedagogy, content, technical/QA, UX/UI, engagement, competitive strategy) + a 9-agent quality fleet.

---

## 1. State of the product (verified)

A self-contained Next.js 14 app (state in localStorage; content in authored TypeScript; AI grading via an API route). Three learning surfaces + support pages.

| Asset | Count (verified) |
|---|---|
| Learning Rooms | **62** (interactive: reading/question/log_analysis/flag/analyst_choice/matching/ordering; 65% pass gate + retry) |
| Learning Path lessons | **17** (long-form deep-dives, ordered 0→incident-report syllabus) |
| Attack scenarios | **18** (live Dashboard stories + standalone) |
| Companies | 5 (each a coherent single-EDR/single-IdP architecture) |
| Task instances across rooms | 227 reading · 220 question · 71 log_analysis · 55 flag · 17 analyst_choice · 12 matching · 5 ordering |

**Genuine strengths (keep and lean into):**
- **The moat:** AI-graded *free-text incident reporting* under a strict **"no-hints"** pedagogy. No major competitor (TryHackMe, LetsDefend, BTLO, CyberDefenders) grades how an analyst *writes up* an incident — they grade fill-in-the-flag. This is the defensible differentiator.
- Vendor-accurate synthetic telemetry (CrowdStrike/Defender/Sentinel/Check Point/AWS/GCP/Azure real field schemas), MITRE ATT&CK mapping, coherent per-company environments.
- High hands-on density — essentially every room has practice, not just reading.
- Thoughtful no-hints engineering (neutral severity badge, benign events also carry MITRE, report button doesn't pulse, per-row verdict removed).

---

## 2. Gap map (the six lenses)

### 🧠 Pedagogy — *the scaffolding is designed but was disconnected*
- **G1 (fixed):** `isLocked()` hard-returned `false` — prerequisites never gated anything. The whole prerequisite DAG was cosmetic.
- **G2/G3:** No recommended spine across the 3 surfaces; the Dashboard (the exam) was reachable/defaulted before the lessons.
- Difficulty cliffs (AD jumps to intermediate without Kerberos as a prereq); analyst-mindset taught late+twice; free-text report writing under-practiced before the graded capstone; MITRE reinforced only once early.

### 📚 Content — *breadth & hands-on density strong; specific depth gaps*
- Missing: **Azure IaaS room** (AWS+GCP existed, Azure didn't) — **fixed this session**.
- Thin/absent: query-*authoring* practice (KQL/SPL/Sigma are read, never written), network forensics/PCAP, memory-forensics depth, ticketing/case-management workflow, ransomware IR as a room, AI/LLM-era threats, MITRE D3FEND.

### 🔧 Technical / QA — *tsc clean; but answer-leaks & orphan demo pages*
- **🔴 `/telemetry` leaked the full attack kill-chain and was linked from the live Dashboard — fixed.**
- Failed-room XP could linger in the global total if the user left via "Back to Rooms" — **fixed**.
- Orphan/demo pages with fake or answer-leaking data: `/leaderboard` (fake), `/investigations/[id]` (leaks verdict), `/ai` (canned replies), `/iocs`, `/mitre`, `/detections`, `/hunts`. Report grader `isReal` uses loose bidirectional substring matching.

### 🎨 UX/UI — *strong once inside; on-ramp was fractured*
- **Stale `DashboardTour`** taught an Alert Queue, a pulsing report button, and per-row Benign/Suspicious/Malicious — all removed features. **Fixed** (steps rewritten, version bumped).
- **Landing CTA** pointed at the Dashboard (exam) not the rooms (lessons) — **fixed**.
- Two onboarding systems fire back-to-back; fake auth signals ("Sign in", hardcoded "Tal Ben Dosa / Admin", Admin in learner nav); Learning Path uses a different design language + external Unsplash images; no mobile navigation.

### 🎮 Engagement — *the "earn moment" is missing everywhere*
- XP/levels/ranks/badges are computed from real activity but update **silently** — nothing celebrates a level-up, rank promotion, badge, or streak.
- **Leaderboard was fake in two contradictory places** — **fixed** (replaced with an honest Rank Progression ladder tied to the real XP thresholds).
- **Streak ignored room/lesson completions** — **fixed**.
- 75% of room tasks are read+MCQ; MCQ distractors aren't explained; the two richest activities (kill-chain board, triage worksheet) live only on the Dashboard.

### 📈 Strategy — *a brilliant single-player demo; the path to "best in market"*
- Table-stakes gaps vs market: no real backend/accounts/verifiable certificate; no hands-on real-tool (live queryable SIEM); no community/persistence (localStorage only).
- The winning play: become *real* (backend, credential), then go all-in on the moat — grading how an analyst **thinks and writes**.

---

## 3. What was implemented this session (quick-wins, verified)

All shipped, `tsc` clean (0 errors), browser-verified:

1. **Removed the `/telemetry` answer-leak link** from the live Dashboard (no-hints violation). *(critical)*
2. **Enabled prerequisite gating** — `isLocked()` now checks that every prerequisite room is *passed* (completedAt); beginner rooms stay open. Makes the landing promise true. *(pedagogy #1 lever)*
3. **Dashboard difficulty defaults to Easy** (was Medium) — beginners' first practical is now a single-host foundation attack.
4. **Fixed the stale DashboardTour** — removed steps teaching the removed Alert Queue / pulsing button / per-row verdict / nonexistent Guided Analysis target; rewrote to the current feed-and-report model; bumped the version so returning users re-see it.
5. **Landing primary CTA → "Start Learning" (/rooms)**; Dashboard demoted to secondary.
6. **Fixed failed-room XP accounting** — a sub-65% attempt now rolls its XP back immediately and persists nothing, so no stray XP survives *any* exit path.
7. **Replaced the fake leaderboard** (both the Progress-page const and the "Full board" link to the fake page) with an honest **Rank Progression** ladder tied to the real `rankFromXp` thresholds.
8. **Fixed the streak** to count room completions, not just dashboard/scenario sessions.
9. **New Azure IaaS Security room** (62nd room) — parity with AWS/GCP; real `azure.activitylogs.*`/`keyvault.*`/`nsgflowlogs.*` fields, an Azure↔AWS↔GCP mapping matching task; registered + numbers updated across the app.

---

## 4. Roadmap — next moves (prioritized)

### Near-term quick wins (high impact / low effort)
- **Wire the "earn moment"** — one reusable celebration toast fired on level-up / rank promotion / badge unlock / streak milestone. All data already exists; nothing fires it. *(highest-leverage engagement fix)*
- **Explain MCQ distractors** — add per-option "why this is wrong" so a wrong answer teaches. (Content pass across question tasks.)
- **De-risk the remaining orphan/demo pages** — delete or clearly label `/ai`, `/investigations`, `/iocs`, `/mitre`, `/detections`, `/hunts`, `/leaderboard`; they carry fake or answer-leaking data.
- **Tighten the report grader** `isReal` to token/exact matching (currently loose bidirectional substring).
- **Onboarding consolidation** — keep the accurate SOCWelcomeModal; make the tour opt-in. Clean up fake-auth signals + move Admin out of learner nav.
- **A "Start Here / My Path" spine** — sequence lessons → matching rooms → first Easy Dashboard session, with "you are here."

### Content depth (via `soc-content-writer` + validators)
- Query-*authoring* practice (a new "write the KQL/SPL" task variant or room), network-forensics/PCAP room, ticketing/case-management room, ransomware-IR room, AI/LLM-era-threats room, MITRE D3FEND lesson.
- Pedagogy re-sequencing: move analyst-mindset early, add Kerberos as an AD prerequisite, insert low-stakes free-text "micro-reports" before the capstone, reinforce MITRE mid-course.

### Big bets (strategic, higher effort)
- **Real backend + accounts + verifiable certificate** (the README shows a Supabase schema already designed) — unlocks persistence, real community, real leaderboard.
- **A queryable log lab** — even a simulated KQL/SPL engine over the existing seeded events closes the #1 employer-facing gap.
- **Adaptive difficulty** — route the per-technique/per-source accuracy already computed into next-event selection (an AI tutor that hunts blind spots).
- **"Weekly Incident"** — an AI-generated fresh, graded scenario on a cadence (generation routes + agents already exist) → return-visit loop.
- **Capstone "Boss Shift"** + **branching investigation** + **threat-actor narrative layer** — teach investigative decision-making and give levels/ranks something to unlock.

---

## 5. Original improvement ideas (engagement, no-hints-safe)
- **Confidence-based answering** on analyst_choice (rate confidence before the reveal; reward calibration) — teaches "knowing when you don't know."
- **Interactive timeline builder** — drag scattered events into order + mark the benign→malicious pivot.
- **"Spot the anomaly" timed micro-challenge** — flash a few log lines, click the one that's off, against a clock.
- **Explain-back as a first-class mechanic** — the student must articulate *why*, graded by the model (extends the no-hints philosophy; hard to brute-force).
- **Bring the kill-chain board & triage worksheet into rooms** as task types (they already exist as Dashboard components).

---

## 6. The agent fleet (9 specialists, `~/.claude/agents/`)
**Content:** `soc-log-generator`, `soc-content-writer`. **Quality:** `soc-content-validator`, `soc-alignment-auditor`, `soc-room-log-auditor`. **Product:** `soc-pedagogy-architect`, `soc-qa-engineer`, `soc-ux-ui-reviewer`, `soc-engagement-designer`.
*(Browser-driving agents — qa, ux — share one preview server; run them sequentially.)*
