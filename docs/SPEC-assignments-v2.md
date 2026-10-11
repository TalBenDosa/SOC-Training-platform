# SPEC — Learning plans v2 (group + personal assignments, module tree)

**Requester:** an org admin who runs a SOC (B2B tenant). **Goal:** prioritise specific learning modules and
practice for **groups** (e.g. "Tier-1 analysts") **and for specific people** ("David gets lessons X, Y and
practice Z"), with a **checklist (tick V)** and a **left-side module tree** showing which modules belong to
which training.

## What exists today (v1)
`public.assignments` (0021): org-wide only, `items: [{kind:'room'|'scenario', id}]`, title/instructions/due_at.
`/api/org/assignments` GET/POST/DELETE (no edit), `AssignmentsPanel` on `/manage` (flat search list, no
instructions field, no target), learner `AssignedWork` on `/rooms` only; completion = rooms + scenarios.

## v2 — scope
### Data (migration `0075_learning_plans.sql`, idempotent, backward compatible)
- `org_groups (id, org_id, name, description, created_by, created_at, updated_at)`, unique (org_id, lower(name)).
- `org_group_members (group_id, user_id, org_id, added_by, added_at)`, PK (group_id, user_id).
- `assignments` gains: `audience text not null default 'org' check in ('org','targeted')`,
  `priority smallint not null default 2 check (1..3)` (1 = high), `personal_user_id uuid null`
  (a user's single **personal plan**; unique (org_id, personal_user_id) where not null),
  `archived_at timestamptz null`.
- `assignment_targets (assignment_id, org_id, group_id null, user_id null)` — exactly one of group/user.
- `items` kinds extended to `room | scenario | lesson | quiz` (+ org-authored ids for room/scenario/quiz/lesson),
  item may carry `priority` (1..3) and `note` (≤300 chars). Existing rows stay valid.
- RLS: staff (`org_admin`, `instructor`) of the org manage groups/targets/assignments; a student may read an
  assignment only if it is org-wide, targets them directly, targets a group they belong to, or is their personal
  plan. Group rows readable by staff only (a student sees only the names of groups that target them, via the API).
  New objects revoked from anon.

### API
- `/api/org/groups` — GET (groups + member ids), POST create, PATCH rename/set members, DELETE. org_admin (+ audit).
- `/api/org/assignments` — GET returns only what the caller is targeted by (students) or everything (staff) with
  per-user × per-item progress for staff; POST/PATCH (edit, reorder, archive)/DELETE; accepts `audience`,
  `targets {group_ids[], user_ids[]}`, `priority`, item `priority`/`note`.
- `/api/org/students/[id]/plan` — GET/PUT the personal plan (ordered items + priority + note) for one learner.
- Catalog for the module tree: server-built tree
  `Learning Path → path → module → lesson` (`LESSON_PATHS`, lesson key `"{path}--{lesson}"`),
  `Rooms → category → room` (`ROOMS_META`), `Quizzes → category → quiz` (`ALL_QUIZZES`),
  `Scenarios → difficulty → scenario` (`SCENARIOS`), `Custom (your org) → type → item` (published org content).
- Completion per item: room `room_progress.completed_at`, scenario any `scenario_history`, quiz
  `quiz_progress.passed`, lesson `lesson_progress.completed_at` (service-role reads, org-pinned).

### Manager UI (`/manage`)
- **Learning plans** panel: left **module tree** (collapsible, search, tick V at any level = select children),
  centre = selected items (drag/↑↓ order, per-item priority + note), right = recipients (whole org / groups /
  specific users — multi), title, instructions, due date, overall priority. Edit + archive existing plans.
- **Groups** panel: create "Tier-1 analysts" etc., add/remove members from the roster.
- **Student page** (`/manage/students/[id]`): **Personal priorities** — the same tree with V checkboxes; saving
  writes that learner's personal plan. Shows each assigned item's status (not started / in progress / done).
- Progress: per plan a users × items matrix (done ✓ / in progress / not started), overdue flags.

### Learner UI
- "My learning plan" card on the dashboard and `/learn` (and keep `/rooms`): items ordered by priority
  (personal plan first), instructions/notes shown, done ✓, due/overdue, deep links to each item.
- "Assigned" chip on assigned items in room/lesson/quiz lists (nice-to-have).

## v2.1 — "Assigned" chips + notifications (migration `0076_notifications.sql`)
- **Assigned chips**: room cards, Learning Path lesson rows (+ an "N lessons assigned to you · M done" count on the
  path page), library lesson cards (org lessons), quiz cards and scenario cards show `Assigned` / `Assigned · High` /
  `Assigned · Low` / `Assigned · Done` for items in any plan the current learner receives. Data: ONE request per page,
  `GET /api/org/assignments?view=assigned-keys` → `{ items: { "kind:id": { priority, due_at, done, personal } } }`
  (built from `loadLearnerPlans`, so the same recipient rules; effective priority = item priority, else plan priority;
  highest wins across plans; earliest due date), cached in memory by `useAssignedItems()` (60 s, per user). Nothing
  renders for guests, users without an org, or unassigned items.
- **Notifications**: `notifications (org_id, user_id, kind, title, body, link, assignment_id, created_at, read_at)` —
  composite FKs to `org_members` and `assignments (id, org_id)` (cascade), in-app links only (`/…`). RLS: a user
  SELECTs their own rows and may UPDATE only `read_at` (column grant) on their own rows; no client INSERT/DELETE
  (service role in the plan routes). Kinds: `plan_assigned` (create → every recipient; edit → NEW recipients),
  `plan_updated` (edit that ADDS items → existing recipients), `personal_plan` (personal plan whose item set changed).
  Archive / unarchive / delete / clearing a personal plan notify nobody; the acting manager, inactive members and
  platform admins are never notified. `src/lib/plans/notify.ts`.
- **Email** (opt-in per save, "Also email recipients", default OFF). Shares the platform's single Resend account
  (resets, invites, cron — possibly the free tier), so it is fenced: only recipients whose notification row was
  actually inserted (none if the table is missing); no second email about the same plan to the same person within
  24 h (`notifications.emailed_at`, set only for rows actually emailed); a per-org daily budget
  (`PLAN_EMAIL_DAILY_BUDGET`, default 50) on the shared rate-limit store — when spent, emails are skipped and in-app
  notifications still go; ≤ 100 per save; sent through Resend's batch endpoint (`sendEmailBatch`, ≤ 100 per call →
  1–2 API calls per save); addresses from the service-role-only `plan_recipient_emails(org, user_ids)` (active
  members only). Fixed subjects ("New learning plan from {org}", "Your learning plan was updated", "Your personal
  priorities were updated"); the plan title only in the escaped body, clipped to 80 chars; no item titles/notes. The
  route awaits the job up to 8 s so the response (and the manager's notice) carries the real outcome
  (`{ notified, email: { emailed, failed, skipped: { budget, dedupe, unconfigured, no_address, cap } } }`); a slower
  job finishes in `after()` (`maxDuration = 300`) and its final counts are audited.
- **API**: `GET /api/notifications` (own, newest 30 + unread count; `enabled: false` without an org),
  `POST /api/notifications/read` (`{ ids }` ≤ 100 or `{ all: true }`) — both through the user's own RLS client.
- **UI**: working bell in the Topbar (unread badge, dialog panel that takes focus and closes on Escape / focus leaving,
  click = mark read + navigate, "Mark all read"; polls every 60 s while visible + one debounced refresh on focus; stops
  polling when the server answers `enabled: false`).

## Non-goals
Realtime push, per-user notification preferences, instructor role access to `/manage` (stays org_admin), gamified
rewards for plans.

## Verification
Unit tests for item sanitising, targeting resolution, completion; migration applied to STAGING with RLS checks
(student sees only own/group/org plans; other-org isolation); tsc, vitest, build, validators. No production
change without explicit approval.
