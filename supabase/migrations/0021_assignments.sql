-- ─────────────────────────────────────────────────────────────────────────────
-- 0021 — Assignments (instructor-directed coursework)
-- ─────────────────────────────────────────────────────────────────────────────
-- An instructor running a semester could not point a cohort at anything: the
-- whole catalogue (90+ rooms, 20+ scenarios) sat open with no ordering, no
-- "do these five by Sunday". That's the difference between a library and a
-- course, and it is the hard blocker on "run a real class on this".
--
-- Design notes:
--  * `items` is a jsonb array of {kind:'room'|'scenario', id} rather than a
--    join table. The referenced ids live in the CONTENT CORPUS (TypeScript, not
--    the DB) — there is no rooms table to foreign-key against — so a join table
--    would buy referential integrity it cannot actually enforce, at the cost of
--    a second table and a migration per shape change.
--  * There is deliberately NO submissions/progress table. Completion is already
--    recorded in room_progress and scenario_history; deriving assignment
--    progress from those keeps one source of truth. A student who finished a
--    room last week is instantly "done" when it's assigned today — which is the
--    behaviour a teacher expects, and the opposite of what a separate
--    submissions table would produce.
--
-- RLS: everyone in the org READS (students must see what they were set);
-- only org_admin/instructor WRITE. Same current_org() tenant boundary as every
-- other org-scoped table, so one college can never see or touch another's
-- coursework.
-- ─────────────────────────────────────────────────────────────────────────────

create table if not exists public.assignments (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid not null references public.organizations(id) on delete cascade,
  title        text not null,
  instructions text,
  items        jsonb not null default '[]'::jsonb,
  due_at       timestamptz,
  created_by   uuid references auth.users(id) on delete set null,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create index if not exists assignments_org_idx     on public.assignments(org_id);
create index if not exists assignments_org_due_idx on public.assignments(org_id, due_at);

drop trigger if exists assignments_touch on public.assignments;
create trigger assignments_touch before update on public.assignments
  for each row execute function public.touch_updated_at();

alter table public.assignments enable row level security;

-- Read: any member of the org (students included — this is their homework).
drop policy if exists "assignments org read" on public.assignments;
create policy "assignments org read" on public.assignments
  for select using (org_id = public.current_org());

-- Write: org staff only, and only into their OWN org (WITH CHECK pins org_id
-- so an instructor cannot create coursework inside another college).
drop policy if exists "assignments staff write" on public.assignments;
create policy "assignments staff write" on public.assignments
  for all
  using      (org_id = public.current_org() and public.current_org_role() in ('org_admin','instructor'))
  with check (org_id = public.current_org() and public.current_org_role() in ('org_admin','instructor'));

revoke all on public.assignments from anon;
grant select, insert, update, delete on public.assignments to authenticated;

comment on table public.assignments is
  'Instructor-set coursework for an org: a titled list of rooms/scenarios with an optional due date. Progress is DERIVED from room_progress/scenario_history — there is intentionally no submissions table.';

-- Verification:
--   -- as an instructor: insert works for own org, fails for another's
--   -- as a student:     select works, insert/update raises RLS violation
--   select id, title, due_at, jsonb_array_length(items) as item_count from public.assignments;
