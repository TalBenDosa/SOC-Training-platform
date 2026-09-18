# Team-SOC — Comprehensive QA (2026-09-18)

Full QA pass over the **Team-SOC multiplayer** feature: server routes + DB (RPC/RLS/gate/cron),
the live room client + realtime/presence lifecycle, and the timeline / grading / after-action
report. Covers the newly-added session-lifecycle work (end, presence halt, owner auto-close,
DB-persisted pause/resume, closed-list) and the pre-existing feature around it.

**Method:** three parallel code audits (server, client, grading) + a self-review of the new
lifecycle code. Static/code-level — no live run (Supabase auth is intermittently unreachable
from the build sandbox). Gates green throughout: `tsc`, `next build`, `vitest` 157/157.

## Severity summary

| Sev | Count | Items |
|---|---|---|
| **High** | 4 | S1 seed/answer-key leak · C1 stuck screen on missed broadcast · C2 observer blocks start · C3 pause-reason lost on reload |
| **Medium** | 11 | S2 lost lifecycle events (seq race) · S3 payload unbounded/XSS · S4 reassign single-seat/instructor · C4 channel leak · C5 token refresh · C6 countdown double-fire · C7 no coverage debounce · C8 owner-timer reset · C9 orphaned running session · C10 AAR unreachable after close · G1 hotwash time origin · G2 report-quality bands dead |
| **Low** | 10 | S5 members TOCTOU · S6 promote seq-retry · S7 member can resume manual pause · S8 instructor can't start · C11 elevation/ack collision · C13 global scopeSet · C14 stale track · G3 dead "4" band · G4 T3 0-vs-null · G5 game-able scores · G6 SITREP over-credit |
| **Fixed this session** | 1 | owner-left auto-close 403 (elected non-staff member could not call `/end`) |

---

## Already fixed (this session)

**X0 — Owner-left auto-close would 403 and never fire.** The client elects any online member to
call `/end` when the instructor drops, but `/end` allowed only staff/SOC-Manager, so a T1/T3
elected client got 403 and the session stayed "live" forever. `/end` now accepts any session
member **only** for the automatic `reason:"owner_left"` path; manual end stays staff/Manager.
(`src/app/api/team/sessions/[id]/end/route.ts`) · verified tsc.

---

## HIGH

### S1 — `session.seed` (the grading answer key) is leaked to every member
`sessions/route.ts:87,91` and `sessions/[id]/route.ts:18,48` return the full session row via
`select("*")`. `buildTeamTimeline(company, difficulty, seed)` is fully deterministic and every
data source it uses is client-bundled (none are `server-only`), and the feed it builds stamps
each event's `expected_verdict` (the key). A member reads `session.seed` from the API and
reproduces the entire incident offline — which logs are the attack, their verdicts, and the
scripted MSEL injects. Defeats the reason injects are staff-only-readable. The client never uses
`seed`, so it's leaked needlessly.
**Fix:** select explicit columns; strip `seed` (and `config`/`scenario_id`) from member-facing
responses, return them only when `iAmStaff`.

### C1 — A client that misses one lifecycle broadcast is stuck forever
`phase`/`paused` are set **only** in the broadcast handler (`page.tsx` ~262-265). The 6-second
reconcile `pull()` only appends to `events`; it does not drive lifecycle. So if a client misses
`session.ended` / `session.paused` / `session.resumed` (tab asleep, socket blip, token expiry,
backgrounded mobile) it keeps rendering the old screen even though the very next pull fetched the
row. Only a reload recovers (initial load reads `status`).
**Fix:** factor an `applyLifecycle(ev)` used by both the broadcast handler and the pull; after each
merge, reconcile to the max-seq `session.*` event.

### C2 — An `observer` on the roster permanently blocks starting
`players` includes observers (`page.tsx:316`) so `allReady` requires them ready, but `iAmPlayer`
excludes observer so they have no ready control. The server mirrors it (`start/route.ts:35` ready-
check is "not instructor"). `AddMemberPanel` offers "observer", so adding one wedges Start with a
generic "N player(s) not ready" error.
**Fix:** exclude `observer` from `players` and from the server ready-check (and the ready
denominator — see C12).

### C3 — Pause reason lost on reload → wrong message + coverage pause can stick
Pause reason/detail live only in the `session.paused` event payload, never on `team_sessions`, and
initial load sets `paused` but not `pausedReason`. After a reload: (1) a manual pause shows the
"not enough of the team / resumes automatically" coverage copy; (2) auto-resume requires
`pausedReason==="coverage"`, so a reloaded elected client won't auto-resume when coverage returns —
if all online clients have reloaded and no staff/mgr is present, the coverage halt never lifts.
**Fix:** return the last pause reason/detail from the API (derive from the latest `session.paused`
event, or add `paused_reason`/`paused_detail` columns) and set on load; reconcile paused/resumed in
the pull (C1).

---

## MEDIUM

### S2 — start/end/pause append their system event without the seq-retry, and swallow the error
The three routes do `nextSeq = max(seq)+1` then `insert(...)` without checking the error — unlike
`apply_session_action` (hardened in 0062). A concurrent RPC action or the cron tick can grab the
same `seq`; the insert fails on `unique(session_id, seq)`, the error is discarded, but the
`team_sessions.status` flip already committed. Result: status changed but the matching
`session.started/paused/resumed/ended` is never appended or broadcast → clients don't transition.
**Fix:** emit these via a retrying insert (mirror 0062) or an RPC, and check the error before `ok`.

### S3 — `apply_session_action` payload is unbounded/unsanitised and rebroadcast verbatim
Any member can call the RPC with arbitrary-size JSONB payloads that are stored append-only and
fanned to every teammate (`broadcast_session_event`). Risks: (a) storage/broadcast DoS within a
session; (b) **stored-XSS across the war room** if any payload field is rendered unescaped. Also
`message.sent` is allowed in any status (gate 0061:49), and a `t1` can `disposition.set` /
`escalation.requested` on any `event_id` they name (no payload-target check).
**Fix:** per-type payload shape/size checks in the RPC; constrain `message.sent` to running/paused;
ensure the client escapes all rendered payload text.

### S4 — `/reassign` breaks the single-seat invariant and can grant instructor powers
`reassign/route.ts` has no single-seat guard (unlike `/members`) and includes `instructor` in
`PLAY_ROLES`. An org_admin can create two `mgr`/`t3`, or reassign someone to `instructor` (grants
`staff.inject`, removes them from the ready-check).
**Fix:** apply the `SINGLE_SEAT` check; drop `instructor` from reassignable roles.

### C4 — Realtime channel leak: async `subscribe` races cleanup
The effect assigns `channelRef.current` only after `await getSession()`; cleanup reads it
synchronously. Under StrictMode double-mount or a fast `me.id` change, cleanup runs before the
channel exists → `removeChannel(null)` no-op → the later-created channel is never removed. Orphaned
`session:${id}` subscriptions accumulate.
**Fix:** cancelled-flag; remove the just-created channel if cancelled when the IIFE resolves.

### C5 — Realtime auth token never refreshed → presence drops on long sessions
`setAuth(token)` is called once at subscribe; no `onAuthStateChange` rewire. On ~1h token expiry the
private channel can drop and reconnect stale, so that client silently disappears from presence —
which now trips the coverage halt (C7), owner-left auto-end (C8), and leave popups with no real user
action.
**Fix:** on `TOKEN_REFRESHED`, `sb.realtime.setAuth(newToken)` and re-track presence.

### C6 — Countdown double-fires and leaks its interval
`startCountdown` is called by `start()` and by the initiator's own `session.started` broadcast, and
its `setInterval` is never stored/cleared. The initiator runs two countdowns (jumpy digits, double
`setPhase`); navigating away mid-countdown leaves an interval calling setState on an unmounted tree.
**Fix:** re-entry guard (`if (countdown!==null) return`) and clear on unmount.

### C7 — Coverage auto-pause has no debounce (owner-left has 30s; this has 0s)
The halt is derived instantly from presence and the elected client immediately POSTs a coverage
pause. A single core player refreshing flashes a full-screen team-wide "Training paused" overlay and
writes a DB pause/resume flap.
**Fix:** a ~10-15s grace/debounce before showing the coverage overlay and firing the coverage
pause. *(Product decision: overlay-only debounce vs also delaying the DB write.)*

### C8 — Owner-left 30s timer resets on every presence sync → may never fire
The effect deps include `online`, and `setOnline(new Set(...))` allocates a new Set each sync, so
the cleanup clears+reschedules the 30s timer on any presence event. In an active room the grace
timer keeps restarting and the auto-end can be delayed or never complete.
**Fix:** depend on a stable membership signature (sorted-key string), or track owner-gone timestamp
in a ref and compute elapsed in one interval.

### C9 — A session where everyone closes their tab is orphaned in `running`
Both auto-transitions require an elected **online** client. If all members close tabs (or all drop
via C5), nothing fires and the session stays `running` (shows "live"/enterable) until an instructor
manually ends it.
**Fix:** a server-side sweep (cron) that ends/pauses `running` sessions with no recent presence/
activity.

### C10 — After-action report is unreachable from the list once the session closes
The list renders `ended`/`debriefed` as a non-clickable `div` (per the requested "closed can't be
entered"), but the AAR only renders inside the room at `phase==="ended"`. So the debrief can't be
revisited from the UI (only by typing the URL). For a training product, the debrief is core value.
**Product decision needed:** keep "no re-entry" but add a **read-only "View report"** affordance on
closed rows (recommended), or leave as-is.

### G1 — HotWash times are measured from lobby ready, not session start
`t0 = events[0].occurred_at`, but `member.ready` events precede `session.started` in the log, so
every absolute time in the hot-wash ("First escalation — 8m 30s", track timestamps) is inflated by
the lobby-to-start gap and disagrees with the AAR metrics (which correctly use `session.started`).
**Fix:** derive `t0` from the `session.started` event (fallback min `occurred_at`).

### G2 — `reportQualityScore` graduated bands are dead (cell is effectively presence-only)
The submit gate requires summary + ≥12-word findings + recommendation + (always-present) verdict, so
every accepted report scores ≥ 87 → `bandHigh(≥85…)` always returns 12; the 60/35 bands are
unreachable. The "Incident report" rubric cell is binary null-or-12 and doesn't discriminate.
**Fix:** raise the quality thresholds well above the 12-word submit floor (and/or reward substance,
e.g. references a case IOC/host/technique) so the bands spread.

---

## LOW

- **S5 — `/members` single-seat is check-then-insert (TOCTOU).** Two concurrent adds of different
  users to `mgr`/`t3` both pass. Fix: partial unique index `(session_id, role) where role in
  ('mgr','t3') and status<>'left'`.
- **S6 — `promote_due_injects` lacks the seq-retry.** A player action colliding with the 5s tick
  raises `unique_violation` and aborts that whole tick (injects retry ~5s later; no loss/double).
  Fix: wrap the per-inject insert in the 0062 retry loop.
- **S7 / C-side — any member can RESUME a manual pause (or spam pause/resume).** `/pause` authorises
  "any member" for both directions and ignores `reason`. Fix: only staff/`mgr` may clear a `manual`
  pause; restrict member-driven transitions to `coverage`; consider rate-limiting.
- **S8 — an `instructor` (orgRole) can't start/reassign/add-members.** Those routes use
  `requireOrgAdmin` while the rest of the feature treats `instructor` as staff. Over-restriction
  (fail-closed), but a real inconsistency. Fix: a `requireOrgStaff` that accepts `instructor`.
  *(Related: two Start paths exist — the route seeds the real timeline; the stale
  `start_team_session` RPC seeds a synthetic 12-event feed. Remove the RPC path to avoid divergence.)*
- **C11 — "take the hunt" collides with escalation ack.** `HuntConsole` emits
  `escalation.acknowledged` for an elevation, so that event_id shows "handled" in T1's tracker and
  T2's inbox. Fix: a distinct `elevation.acknowledged` type.
- **C13 — global `scopeSet` unlocks containment for every case.** Once any scope is set, every
  acknowledged+reported ticket can request containment. Consistent with "one shared case" — confirm
  intent.
- **C14 — `.track()` ready flag is a stale closure snapshot.** Negligible (setReady re-tracks).
- **G3 — `bandHigh(x,2,1,1)` makes the "4" tier unreachable** in help-desk/hunt-yield/verifiable-
  rule/ATT&CK cells (only 0/8/12). Intentional coarseness? If not, use distinct thresholds.
- **G4 — T3 "did nothing" scores 0 in some cells, null in others** — cross-role fairness
  inconsistency (idle T3 ~0%, idle TI shows "—"). Decide per role and apply consistently.
- **G5 — deterministic quality scores are game-able** (word count / field presence). Known limit;
  optionally require a real case-token reference.
- **G6 — `mgmtRespondedRate` over-credits** a single/unrelated SITREP after an inject. Fix: pair each
  inject to the nearest following SITREP one-to-one within a window.

---

## Verified correct (skeptically checked)

- **Append-only integrity:** `session_events/state/injects` grant only SELECT; RLS is SELECT-only;
  all writes go through SECURITY DEFINER RPCs — clients can't forge/mutate the log.
- **Spoiler containment (except S1):** injects are staff-only readable; promotion never copies
  `expected_action` into emitted events.
- **Realtime authz (0050):** private `session:<uuid>` topic gated by `is_team_member`; malformed
  topic → NULL → deny.
- **Gate deny-by-default (0061):** trailing `else false`; server/system types hard-blocked from
  client origin; new action types keyed to role AND `status='running'`; `staff.inject`
  instructor-only. No wrong-role/phase action in the enumerated set.
- **Org isolation on create:** org_id from JWT, invitees filtered to active members of that org;
  start/reassign/members re-verify `sess.org_id===user.orgId`; GET requires member-or-staff.
- **Pause-clock fold-in is race-safe** (`.eq("status", sess.status)` guard folds `paused_ms` once).
- **0064 pacing is correct:** `started_at + (paused_ms + due_offset_ms)`; skipped while paused;
  `status='fired'` prevents double-fire; long/repeated pauses preserve gaps, no burst on resume.
- **RPC idempotency + optimistic concurrency** (idempotency_key, p_expected_seq) preserved.
- **seq dedupe / reconcile pagination** (seqSeen + maxSeqRef, 30×1000 pages) correct.
- **`presenceReady` gate** genuinely prevents a false halt at start; fails safe if presence never
  connects.
- **Leave-popup diff** does not fire on first sync (prevOnlineRef starts empty); capped + expiring.
- **Report robustness:** `computeReport`/`HotWash` handle empty/solo/partial logs — no crash, every
  percentage denominator-guarded; un-instrumented rubric cells return `null` and are excluded.
- **Timeline generation:** strictly-positive monotonic offsets; collision resolver never overwrites
  an attack; benign fill drops/dupes nothing; channel mapping correct; `easy` path intentional;
  noise pool excludes tp/escalate.
- **List enterable logic:** running/lobby/paused enterable and correctly styled; only ended/
  debriefed gated.

---

## Recommended remediation order

1. **High, low-risk correctness:** S1 (strip seed), C1 (reconcile lifecycle in pull), C2 (observer
   start), C3 (pause reason on load — pairs with C1).
2. **Medium robustness:** S2 (retry system-event insert), C6 (countdown guard), C8 (owner-timer
   stable deps), C5 (token refresh), C7 (coverage debounce), G1 (hotwash t0), G2 (report bands).
3. **Hardening / product calls:** S3 (payload caps + escape), S4/S7/S8 (authz), C9 (server reaper),
   C10 (read-only AAR — product decision), the Low/grader nits.
