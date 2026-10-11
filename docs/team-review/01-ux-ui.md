# Team-SOC multiplayer — UX/UI review (beginner-analyst lens)

> Reviewed from a fresh dummy run-through, sitting beside a first-time team. Scope: session
> builder + lobby (`src/app/(app)/team/page.tsx`), the live room and every role console
> (`src/app/(app)/team/[id]/page.tsx`), and the shared feed / log detail
> (`src/app/(app)/dashboard/EventFeed.tsx`). Cross-checked against `docs/SPEC-team-ux-ui.md`
> and `docs/SPEC-team-t1.md`. Code-only review — no changes made.

---

## (a) Top 5 highest-impact problems, ranked

### 1. 🔴 The help-desk ticket's "Reject (vishing)" button LABEL names the correct answer
**File:** `src/app/(app)/team/[id]/page.tsx`, `InjectFeed`, lines ~1184–1188.
```tsx
<Button variant="primary" ... onClick={... decision:"handled", response:"verified caller, no code shared" ...}>Handle</Button>
<Button variant="outline" ... onClick={... decision:"rejected", response:"denied — likely vishing" ...}>Reject (vishing)</Button>
```
The whole pedagogical point of a help-desk inject (e.g. "a vendor called asking for an MFA code") is to see whether Tier-1 can *recognize* social engineering without being told. The second button's visible caption is literally **"Reject (vishing)"** — it hands the analyst the correct classification before they've reasoned about anything. This is the single worst violation of the platform's own "no hints" golden rule found in this review: it's not a subtle color cue, it's the answer, printed on the button.
**Fix:** Neutral action labels that don't name the attack technique, e.g. `Handle — provide info` / `Refuse & escalate to security`. Keep the technique name (`vishing`) only in the after-action report / instructor debrief, never in the live UI.
**Why it matters:** this single line can invalidate the entire inject for every team that plays the session, silently, forever — no analyst will ever be "surprised" by this ticket again once anyone has seen the buttons.

### 2. 🔴 The Threat-Intel "repository" tells TI the IOC is fake before they verify it
**File:** same file, `TIConsole` / `INTEL_REPO`, lines ~1272–1276.
```ts
{ id: "a3", source: "OSINT (unverified)", title: "Reported C2 IP for this cluster", ioc: "8.8.8.8",
  note: "⚠ Looks like a public resolver — likely a bad IOC. Verify before publishing.", decoy: true }
```
This `note` string renders unconditionally in the card (`{a.note && <p>{a.note}</p>}`), in amber, right under the advisory — before the analyst has done any verification. The exercise is explicitly designed to teach "don't relay an unverified IOC" (per the code comment itself), but the UI pre-grades the IOC for the student. There is nothing left to teach once the warning is already on screen.
**Fix:** Don't ship the verdict as UI copy. Either (a) remove the `note`/`⚠` line entirely and let the analyst cross-reference the feed themselves, or (b) reveal it only after they've clicked "use this IOC →" and attempted to publish, as a post-hoc teaching moment in the AAR — not as a pre-emptive warning label.

### 3. 🔴 The 🚩 log-anchored escalate button bypasses both the claim lock and the disposition step
**File:** `team/[id]/page.tsx`, `onEscalate` prop wired at lines ~460–473; the claim banner lives inside `T1Console`'s `<Card>` at lines ~811–820; the modal (which fully covers that card) opens at line 838; the enable-condition `canEscalate` (line 750) never checks a disposition.
- Clicking 🚩 on a log immediately sets `t1Sel` and opens the report modal — it never calls `claim()` and never checks `claimerOf(sel)`. Since the modal is a `fixed inset-0 z-50` overlay, the "🔒 claimed by X — Take over?" banner (which *does* exist, but only in the underlying Card) is invisible the whole time the modal is open. **Two Tier-1 analysts can flag and escalate the exact same log at the same moment with zero collision warning** — the one collision-prevention mechanism the spec calls out (§2.1 "Claim/Assign") is silently skipped on this path.
- Separately, `canEscalate` requires `summary + rationale(≥12 words) + ≥1 IOC + severity` — but **not** a prior `disposition.set`. A brand-new player can 🚩 any log straight into a full escalation without ever pressing True Positive / Suspicious first. This breaks the taught workflow (triage → escalate) and quietly wrecks the "disposition accuracy" headline metric for that log (it never gets a disposition at all).
**Fix:** In the feed's `onEscalate` handler, check `claimerOf(id)` first and surface the same claim banner *inside* the modal header (not just in the card behind it). Either soft-require a disposition before allowing 🚩 (auto-set `true_positive`/`suspicious` when the modal is opened from the flag, prompting the user to confirm), or explicitly show "no disposition set yet" in the modal so the gap is visible, not silent.

### 4. 🟠 Zero triage-progress feedback in the shared feed itself
**File:** `EventFeed.tsx` — `EventFeedProps` (lines 1069–1097) has no `dispositions`/`claims` prop at all; `EventRow` (lines 900–1058) renders every row identically regardless of state. Meanwhile `team/[id]/page.tsx` already computes `dispositions` (line 310) and `claims` (lines 700–709) — they're just never passed down to the feed.
A beginner Tier-1 is looking at a 60–120-row raw SIEM feed. There is **no dot, checkmark, strikethrough, or dimming** on a row once it's been dispositioned, claimed by a teammate, or already escalated — that state only exists as a text suffix (`· true_positive`) inside a separate `<select>` dropdown in the console on the right. At any realistic feed size this causes: re-opening logs already handled, two people working the same row (see #3), and a rising sense of "did I already do this?" that is exactly the anxiety a real triage queue is supposed to prevent (spec principle 6, "calm under load").
**Fix:** Pass `dispositions` + `claims` into `EventFeed`/`EventRow` and render a small, neutral (non-severity-coded, so it doesn't leak anything) badge on the row: `✓ triaged`, `🔒 claimed`, `↗ escalated`. This is additive-only, low risk, and directly serves the platform's own "no answer leakage" rule since it reflects *the player's own actions*, not ground truth.

### 5. 🟠 Tier-3's console is still a wall of always-open cards, contradicting the platform's "one dominant action" rule
**File:** `team/[id]/page.tsx`, lines 480–495 (render tree) + `HuntConsole` (1200–1227) + `ScopeConsole` in `"confirm"` mode.
For `role === "t3"`, the right rail stacks, fully expanded, in this order: `T2Console` (escalations inbox card, possibly + an "execute isolation" card), then `HuntConsole` (hunt form card), then inside `HuntConsole` a second `ScopeConsole` card (confirm/amend), then (conditionally) `InjectFeed`, then the `SecondaryPanels` accordion. That's **up to 5 full-height cards** in a 380px column before a first-timer even knows where to look. The doc's own gap analysis (G-03) marks this "✅ done", but the fix only folded *Team Intel / Activity / War-room* into an accordion — it did **not** touch the fact that T3 gets two separate primary consoles (T2Console *and* HuntConsole) stacked on top of each other, each with its own CTA, which is exactly the "role-focus: one dominant action" violation principle 1 warns against.
**Fix:** For T3, either (a) fold the escalation inbox into a collapsed-by-default summary ("3 hard cases waiting — expand") since Hunting, not the inbox, is T3's dominant action, or (b) tab the two consoles ("Inbox" / "Hunt & Scope") instead of stacking both fully open.

---

## (b) Per-role console findings

### T1 (`T1Console`, lines 683–899)
- ✅ **Works well:** the directive text ("Open a log in the feed and hit 🚩 … or pick one below") explicitly bridges the two entry points — good, deliberate signposting for a mechanism that would otherwise be confusing (see §(c)).
- ✅ **Works well:** "My escalations" status tracker (sent → acknowledged → bounced/resolved, lines 790–801) closes the feedback loop nicely — a beginner can see their own hand-off's fate without asking anyone.
- 🟡 The `"Pick a log ▼"` dropdown (line 804) lists events in raw chronological order, not sorted by severity, and with no "already handled" marker in the visible text besides an appended verdict string — at scale this becomes a long, undifferentiated list to scroll through. (Spec already flags this as 🔧 — confirmed still true in code.)
- 🟡 The live quality-gate line (line 887) is a single dense, dynamically-concatenated sentence (`"Needs before escalating: summary · observations (5/12 words) · ≥1 IOC · severity"`) in small gray text below the fold of a scrollable modal. It only ever shows the *negative* state — there's no positive confirmation ("✓ all set") when the gate opens, so a beginner has no positive reinforcement telling them why the button just became clickable. A 4-item checklist with icons (✓/○) would be far easier to scan than parsing a run-on sentence.
- 🟡 `MIN_RATIONALE_WORDS = 12` in code (line 668) vs. `docs/SPEC-team-t1.md` §5.3 which targets ≥20 words — not a player-facing bug, but worth reconciling doc vs. code before grading claims are made in training materials.

### T2 / T3 shared inbox (`T2Console`, lines 905–995)
- ✅ **Works well:** "Open the flagged log (full detail)" (line 944) reuses the exact same `DetailPanel` as the single-player dashboard — a student who trained solo instantly recognizes the UI (spec principle 8, consistency). This is one of the strongest pieces of the whole feature.
- ✅ **Works well:** "Escalations for you (N)" as a literal task counter directly satisfies the "waiting for you" clarity principle.
- 🟡 **Canned, non-editable reasons on negative actions.** "Bounce" (line 961) always sends the fixed string `"needs a clearer indicator / mechanism"`; "Deny" in `LeadConsole` (line 1046) always sends `"not warranted"`. T1 sees this text as if T2 personally wrote it — it wasn't. This both removes a real communication-skill rep (writing a clear rejection) and can read as dishonest/robotic to the receiving player. Give these a required short text field instead of a hardcoded string (mirrors the effort already put into the escalation report's own free-text fields).
- 🟡 "Investigate in EDR" (line 921) calls `window.open(...)` with no check for a popup-blocked `null` return — if the browser blocks the popup (common default), the button silently does nothing and the analyst has no idea why. Add a fallback: if `window.open` returns falsy, show a note ("Pop-up blocked — allow pop-ups for this site, or click here").

### T3 Hunt (`HuntConsole`, lines 1199–1227)
- 🟡 The "Log hunt finding" button gate (`f.hypothesis.trim().length < 8`) has **no visible feedback at all** when disabled — no counter, no hint text — unlike T1's escalation gate, which explains itself. Inconsistent gating UX across roles trains the beginner differently depending which console they land on.
- 🔴→🟡 (functional bug, not just UX) **`ScopeConsole`'s confirm-mode fields go stale.** `ScopeConsole` (lines 998–1026) seeds its inputs via `useState(scope?.hosts.join(", ") ?? "")` — a one-time initializer. If T2 sets or updates the scope *after* T3's `HuntConsole` has already mounted, T3's text boxes will **not** refresh to reflect it; T3 can unknowingly confirm a stale/blank scope over a newer one T2 just proposed. Given the whole point of "confirm" is to review T2's latest proposal, this is a real hand-off-integrity bug, not just cosmetics. Fix: key the component on `scope` (e.g. `useEffect` to sync fields when `scope` changes) or make it fully controlled from the prop.

### Lead / SOC Manager (`LeadConsole` + `MgrConsole`, lines 1029–1129, 1323–1362)
- ✅ **Works well:** the Situation-Board substitution for Lead/Mgr (`SituationBoard`, lines 1819–1875) genuinely keeps raw logs out of the coordinator's hands, matching §3.7 and avoiding the "Lead who dives into the feed and stops coordinating" anti-pattern called out in the spec.
- 🔴→🟡 **Approve has zero friction; Deny has a canned one.** The primary CTA "Approve" (line 1045) fires immediately with no reasoning field of any kind — the spec's own narrative says the Lead "must ask what's the impact before approving," but nothing in the UI asks anything. Meanwhile Deny sends a hardcoded, non-editable reason. The net effect: the role most explicitly about *judgment* has the least friction on its primary action. Add an optional-but-encouraged one-line "why" field next to Approve (not blocking, so it doesn't slow a confident correct call, but present so the habit is modeled).
- 🟠 **Role-scope asymmetry between `lead` and `mgr`.** `role === "lead"` renders only `LeadConsole` (approvals + Decision Log + SITREP). `role === "mgr"` renders **both** `LeadConsole` *and* `MgrConsole` (workload + passdown) — line 486 vs. 489. If a session has both a Lead and a Manager, the Manager ends up with strictly more panels/power than the Lead (everything the Lead has, plus shift management), which contradicts the ROLE_GUIDE text describing them as distinct, bounded roles. A beginner Manager sees a noticeably busier screen than a beginner Lead for what the guide presents as parallel authority.

### Detection Engineer / Threat Intel (`DEConsole`, `TIConsole`)
- ✅ **Works well:** DE's live back-test count with a visible query syntax hint (`fields: source · host · user · ip · mitre · rule · vendor · event · severity — AND-ed`, line 1254) is genuinely well scaffolded for a beginner who's never written a query language before.
- 🔴 TI's decoy-IOC leak — see top-5 #2.

### Instructor (`InstructorPanel`, `InjectFeed`)
- ✅ Simple, appropriately minimal — roster/presence + a 3-kind inject composer is exactly the right amount of control surface for staff.
- 🔴 The vishing-ticket label leak — see top-5 #1.

### Shared shell (`SharedCase`, `FeedFilterBar`, directive banner, `RoleGuideModal`)
- ✅ **Works well — call this out explicitly:** the always-visible per-role directive banner + the once-per-role `RoleGuideModal` (mission / steps / hand-off / "you're measured on" / overall flow) is a genuinely strong first-run onboarding pattern. It answers "what do I do now" without a facilitator, which is exactly what the task asked to verify. Keep this pattern; it's worth reusing anywhere else in the product that currently lacks it.
- ✅ `SharedCase`'s collapsible summary bar (lines 552–563) correctly keeps the feed as the dominant visual element per principle 2 — good restraint, this is the fix the tenant explicitly asked for (SLA bar / nudge removal) done right.
- 🟡 The lobby's "Create & open lobby" flow (`team/page.tsx`, line 169) is only gated on "≥1 invite" — a staff member can launch a session with, say, only a Manager and zero Tier-1s and get no warning at all. A light, non-blocking notice ("No Tier-1 assigned — the feed won't get triaged") would catch an easy setup mistake before the lobby opens.

---

## (c) The 🚩 escalation flow, specifically

**What works:**
- The modal is genuinely well-designed as a *form*: the "Flagged log · #seq" header with severity/source/host/user chips (lines 847–856) gives the analyst a persistent anchor to what they're reporting on, so they can't lose track mid-form.
- IOCs added via ＋IOC on the log's own fields (rather than retyped) is exactly the right idea for reducing transcription error — where it's actually wired (see caveat below).
- The dual entry point (🚩 inline in the log vs. "Write escalation report — #seq" / dropdown in the console) is a reasonable **design intent** — it serves two different mental models (I'm already reading this one log vs. I want to see my whole queue). It is not inherently confusing *if* both paths keep the user oriented to the same log, which they do (both drive the same `sel`/`setSel` state, both show `#seq` in the resulting button/header). The one real problem isn't "two buttons," it's that opening via 🚩 hides the claim-conflict state (see top-5 #3) — fix that and the two-entry-point design is fine as-is.
- The disabled-until-ready CTA + inline "what's missing" line does correctly implement a hard quality gate (no escalation goes through with zero IOCs) — the mechanism is sound, only its *presentation* (dense sentence, no positive state) needs polish (see T1 section above).

**What's broken or leaky:**
1. Claim/soft-lock is bypassed via 🚩 → collision risk between two Tier-1s (top-5 #3).
2. Disposition is not required before escalation is allowed (top-5 #3) — a log can go straight from "never looked at" to "escalated."
3. ＋IOC is only wired for the three **Basic Information** rows (Username/Hostname/IP Address — `EventFeed.tsx` lines 619–651, `canIoc` check). It is **not** wired for SHA256 hashes, domains, or any other field surfaced further down in **Detailed Log Data** (lines 672–724) — those rows only get "Check Hash/IP/Domain · Threat Intel" buttons, no "+IOC". Since file hashes are frequently the single most important IOC in a malware chain (and the PuTTY-trojan example scenario used throughout the specs literally hinges on a hash), the analyst has to hand-retype a 64-character SHA256 into the free-text box — exactly the transcription risk the click-to-add feature was built to eliminate, missing precisely where it matters most.
4. No positive confirmation when the quality gate is satisfied (cosmetic, covered above).

**Fix priority for this flow specifically:** (1) claim-check on the 🚩 path, (2) wire `onAddIoc` into the hash/IP/domain buttons in the Detailed Log Data section (small, mechanical change — those buttons already have the value in scope), (3) checklist-style gate UI, (4) soft nudge toward setting a disposition before/alongside escalating.

---

## (d) Quick wins vs. bigger redesigns

### Quick wins (small diff, high value)
- Reword `InjectFeed`'s "Reject (vishing)" → a neutral label (top-5 #1). *Single line, highest-value fix in this whole review.*
- Remove/relocate the decoy `note` in `INTEL_REPO` (top-5 #2). Single object literal edit.
- Wire `onAddIoc` onto the hash/IP/domain buttons in `EventFeed.tsx`'s Detailed Log Data loop (§c-3) — the value is already in scope at that call site.
- Add a claim check at the top of the feed's `onEscalate` handler (top-5 #3, first half) — reuse the existing `claimerOf`/banner logic that already exists for the dropdown path.
- Give "Bounce" and "Deny" a required short text field instead of a hardcoded reason string (per-role §T2/§Lead).
- Add a `null`-check + inline note after `window.open()` for "Investigate in EDR" (T2/T3 section).
- Non-blocking "no Tier-1 assigned" notice in the session builder (`team/page.tsx`).

### Bigger redesigns (real effort, still worth scheduling)
- Surface `dispositions`/`claims` state as badges directly on `EventRow` (top-5 #4) — requires threading two new props through `EventFeed`/`EventRow` and deciding on neutral (non-leaking) badge styling.
- Restructure T3's right rail into tabs ("Inbox" / "Hunt & Scope") instead of stacked always-open cards (top-5 #5).
- Fix `ScopeConsole`'s stale-initial-state bug by making it properly reactive to prop changes (functional correctness, not just polish).
- Rebalance `lead` vs. `mgr` console scope so the two roles feel like parallel authorities rather than one being a strict superset of the other.
- Add a lightweight "why" prompt on Approve in `LeadConsole` to mirror the reasoning friction already present (in canned form) on Deny.

---

## Cross-cutting notes (not top-5, but worth recording)

- **RTL:** the entire product is `<html lang="en">` with no `dir="rtl"` anywhere in the app (`src/app/layout.tsx`), and every string encountered in the team feature is English. RTL is therefore **not applicable by design** — this is a deliberate, consistent choice, not an oversight, and nothing in the team feature leaks Hebrew or breaks LTR assumptions.
- **Responsiveness:** the running-phase grid (`grid lg:grid-cols-[1fr_380px]`) correctly collapses to a single column below `lg`, and modals (`max-w-lg w-full p-4`) fit a ~400px viewport fine. The one rough edge: `EventFeed`'s table has `min-w-[720px]` inside an `overflow-x-auto` wrapper, so the shared feed — the single most important artifact in the room — requires horizontal scrolling on any phone-width viewport. Not urgent (the product is clearly desktop/classroom-first) but worth a conscious decision rather than an accidental one.
- **Focus states:** the shared `<Button>` component has a consistent, visible focus ring (`focus:ring-2 focus:ring-cyber-400/50`), so every CTA built from it is keyboard-accessible. A number of raw `<button>` elements written directly in `team/[id]/page.tsx` and `EventFeed.tsx`'s `DetailPanel` (the 🚩 CTA, ＋IOC, pivot chips, accordion chevrons, modal close `×`) rely on the browser's default focus outline instead of the app's own ring style — functionally fine, but visually inconsistent for keyboard users switching between a styled `Button` and an unstyled `<button>` a few pixels away.
- **`expected_verdict` on the client:** `computeReport()` reads `expected_verdict` straight out of the same `events` array that's populated live during the `running` phase (via realtime broadcast + the 6-second DB reconcile poll) — the ground-truth field is architecturally present in the browser well before `session.ended`. This mirrors the existing single-player dashboard's trust model (`useLiveEvents.ts` does the same), so it is **not a regression introduced by the team feature** — but it does mean the platform's own stated principle ("`expected_verdict`/answer-key never on the client before `ended`") is not actually enforced anywhere in the stack today, single- or multi-player. Flagging for awareness even though fixing it is a security/architecture decision outside this UX review's scope.

---

## Executive summary (≤200 words)

The shared shell — directive banner, first-use `RoleGuideModal`, collapsible Shared Case, log-consistent `DetailPanel` reused everywhere — is genuinely strong onboarding and a first-time team can plausibly run the exercise without a facilitator. The escalation-report modal is well-built as a form. But two lines of copy break the platform's core "no hints" promise outright: the help-desk ticket's **"Reject (vishing)"** button literally names the attack technique it's testing for, and the Threat-Intel repository's decoy advisory prints **"likely a bad IOC"** before the analyst verifies anything — both should be fixed before any real cohort plays this. Structurally, the 🚩 flag-to-escalate shortcut silently skips the claim/soft-lock (two Tier-1s can double-escalate the same log) and skips disposition entirely, and the shared feed gives no visual sign of what's already been triaged or claimed, which will cause real confusion at realistic feed sizes. Tier-3 still carries a stack of always-open cards despite the doc claiming this was fixed. None of these require a redesign — each is a scoped, file-and-line-level fix, listed with concrete replacements above.
