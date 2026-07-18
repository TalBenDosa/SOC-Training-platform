# UX, Accessibility & Engagement — Findings + Upgrade Recommendations

**Method:** (1) a hands-on "new student" walkthrough of the live app (cleared browser → landing → rooms → a room → mobile → dashboard), (2) a code-level accessibility audit, (3) gamification/engagement assessment.
**Note on external research:** the deep-research web workflow for gamification/UX evidence was **blocked by API rate-limiting** on this run (0 sources returned). The evidence points below draw on established HCI/learning-science principles (Nielsen Norman Group heuristics, WCAG 2.1 AA, Self-Determination Theory, Duolingo-style habit research) and the in-session UX assessment already done — flagged as such. A clean re-run of the external research is worth doing when limits clear.

---

## A. Student walkthrough — friction log (what I actually hit)

### Landing page
- 🟡 **Two-to-three competing entry points.** Header has "Sign in" + "Enter SOC"; hero has "Start Learning" + "Open SOC Dashboard". As a beginner I'm unsure which is *the* way in. (Primary CTA is now correctly "Start Learning" → good.)
- 🔴 **"Sign in" implies an account that doesn't exist.** I clicked it expecting to register; the app is localStorage-only. This erodes trust on second 1 and makes me worry my progress is tied to a login. The sidebar also hardcodes a real name ("Tal Ben Dosa / Admin").
- 🟡 **The hero "LIVE ALERT FEED" is intimidating jargon for a true beginner** — "LSASS MiniDump via comsvcs.dll", "Encoded PowerShell from WINWORD.EXE" — shown *before* I've learned anything. Impressive to a pro, alienating to the zero-knowledge learner the product targets.

### Rooms list (/rooms)
- 🔴 **No "Start Here" affordance.** Prerequisite locking now works (locked rooms show "Complete Introduction to Cybersecurity first" — good), but nothing positively points me to the *one* room to begin. I face 62 cards, most locked, and have to hunt for the open one. A beginner's first decision should be made *for* them.
- 🟢 The lock messages are clear and specific — this is a real improvement and should stay.

### Inside a room (/rooms/intro-cybersecurity)
- 🟢 Clear "Task 1 of 9", clean reading, good beginner analogy ("Imagine you own a house…"). This part works well.
- 🟡 **A long run of the same task type** (reading → reading → MCQ) with a flat "Mark as Read" rhythm — predictable, low interactivity (confirmed in the earlier engagement review: ~75% of room tasks are read+MCQ).

### Mobile (375px)
- 🔴 **No navigation on a phone.** Inside the app the sidebar is `hidden md:flex` and there is **no hamburger/drawer** — `hasHamburger: false` confirmed. A phone student who finishes a room literally cannot navigate to another section. The app is desktop-only in practice.
- 🟢 No horizontal body overflow on the pages checked (good responsive discipline where it exists).

### Dashboard (the densest screen)
- 🟡 For a beginner the Dashboard is a wall of dense filters, a streaming feed, and stats at once. (The onboarding modal helps, and progressive disclosure of advanced filters is already done — keep that.)

---

## B. Accessibility audit (code-verified — WCAG 2.1 AA lens)

- 🔴 **`prefers-reduced-motion` is not honored anywhere** (grep: 0 hits across `src/` and Tailwind config). The platform animates constantly — a live streaming feed, framer-motion row/drawer/tour transitions. A motion-sensitive user (vestibular disorders) has **no relief**, which is a direct WCAG 2.3.3 / motion concern. **Highest-impact a11y fix.**
- 🔴 **Zero `aria-*` attributes across the entire `.tsx` codebase.** Custom interactive elements — clickable table rows in the feed, the IOC-tagging notebook, drag-and-drop matching/ordering tasks — expose no ARIA roles/labels/state to screen readers. Semantic HTML gives *some* free structure, but these custom widgets are effectively invisible/unusable to a screen-reader learner.
- 🟡 **No skip-to-content link** (the grep hits were text like "Skip" inside lessons, not a real skip link). Keyboard users must tab through the whole sidebar on every page.
- 🟡 **Focus styling relies on the browser default.** No custom `focus-visible` ring in `globals.css`; on the dark custom theme the default outline can be hard to see. Not broken (no harmful `outline:none` reset — good), but focus should be explicitly styled to be visible against the dark palette.
- 🟢 Images that exist carry `alt` (the lesson `<img>` uses `alt={query}`). Text/dashboard app, so few images — low risk here.

---

## C. Gamification & engagement assessment

*(Grounded in the prior in-session engagement research + SDT / habit-formation principles; external citations pending a research re-run.)*

**What's there and healthy (KEEP):**
- 🟢 XP, levels, ranks, 65% mastery gate + retry, per-company progression, the 8-minute SLA — these give real *competence* signals (SDT).
- 🟢 The **honest rank-progression ladder** (replaced the fake leaderboard) — correct call: leaderboards demotivate lower-ranked learners; a personal ladder toward named ranks supports *competence* without the social-comparison downside.
- 🟢 The threat-actor **narrative** ("analyst on shift", named companies) creates situational immersion.

**What's weak / backfiring (FIX):**
- 🔴 **The "earn moment" is missing.** XP/levels/badges/streak all update *silently* — there is no celebratory feedback when you level up, earn a badge, or hit a streak. This is the single biggest, cheapest motivation win: the data exists, nothing celebrates it. Celebratory feedback at the moment of achievement is the core of the "one more session" pull.
- 🟡 **Streak has no visible ambient presence** — it lives buried on the Progress page. Habit mechanics (Duolingo) work because the streak is *always in view* and gently at stake. (The streak-counts-rooms bug is now fixed — good.)
- 🟡 **MCQ distractors aren't explained** — a wrong answer just reddens; it doesn't teach *why* the other option was wrong. This is a missed competence-building + engagement moment.
- 🟢 **Avoided correctly:** a competitive global leaderboard (was fake, now removed) — keep it removed; SDT evidence is that public ranking harms the majority who aren't at the top.

---

## D. Prioritized upgrade recommendations

### 🔴 High impact — do first
1. **Wire the "earn moment"** — one reusable celebration toast/animation fired on level-up, rank promotion, badge unlock, and streak milestone. All the data already exists and is computed; nothing fires it. Cheapest, highest-motivation win.
2. **Honor `prefers-reduced-motion`** — a single global CSS media query that reduces/disables the feed animation and framer-motion transitions for users who ask for it. Small change, real accessibility + comfort win.
3. **Add a "Start Here" affordance on /rooms** — a highlighted "Begin here → Introduction to Cybersecurity" card or ribbon so a beginner's first choice is made for them.
4. **Add mobile navigation** — a hamburger/drawer in the app layout so the platform is usable on a phone at all.

### 🟡 Medium impact
5. **Clean up fake-auth signals** — relabel "Sign in" to "Continue (no account needed)" or remove it; drop the hardcoded "Tal Ben Dosa / Admin" for a generic user; move "Admin Panel" out of the learner nav.
6. **Make the streak ambient** — surface the flame + level in the persistent top bar, not just on the Progress page.
7. **Explain MCQ distractors** — add per-option "why this is wrong" so a wrong answer teaches.
8. **Add ARIA to the custom widgets** — roles/labels/state on the clickable feed rows, IOC-tagging, and matching/ordering drag-drop; add a skip-to-content link; style a visible dark-theme focus ring.
9. **Soften the beginner on-ramp** — consider a gentler landing hero for first-time visitors, or a one-line "New here? Start with the basics — no experience needed" reassurance near the primary CTA.

### 🟢 Keep / don't break
- The prerequisite locking, the honest rank ladder (no competitive leaderboard), the mastery-gate + retry, the progressive disclosure of advanced dashboard filters, and the narrative framing — all evidence-aligned; keep them.

### ⛔ Avoid
- A public competitive leaderboard (harms the majority not at the top).
- Punitive streak mechanics / "you lost your streak!" shaming.
- Rewarding speed over correctness in any gamified metric (a fast wrong answer must never out-score a slow right one).
