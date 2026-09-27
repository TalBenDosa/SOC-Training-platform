-- ─────────────────────────────────────────────────────────────────────────────
-- 0075 — Learning plans v2 (groups, targeted + personal plans, richer items)
-- ─────────────────────────────────────────────────────────────────────────────
-- 0021 shipped org-wide coursework only: every assignment went to the whole
-- org, items were rooms/scenarios, and there was no way to say "Tier-1 analysts
-- do these five" or "David, these three first". A SOC running this as a B2B
-- tenant needs exactly that (docs/SPEC-assignments-v2.md). This migration adds:
--
--  * org_groups / org_group_members — named cohorts inside an org
--    ("Tier-1 analysts"). Membership rows reference org_members, so removing
--    someone from the org drops them from every group automatically.
--  * assignments.audience ('org' | 'targeted'), priority (1 = high .. 3 = low),
--    personal_user_id (a learner's single PERSONAL plan) and archived_at.
--  * assignment_targets — who a targeted plan is for: exactly one of a group or
--    a user per row.
--
-- BACKWARD COMPATIBLE / NON-DESTRUCTIVE:
--  * Every new column has a default that reproduces the v1 behaviour: existing
--    rows become audience='org', priority=2, not personal, not archived — so
--    they stay visible to the whole org exactly as before.
--  * `items` keeps its jsonb shape; v2 only ADDS kinds (lesson | quiz) and the
--    optional per-item priority/note. The array itself is still validated in
--    the API (ids must exist in the catalogue or the org's published content),
--    for the same reason 0021 gave: the content corpus lives in TypeScript, so
--    there is nothing in the DB to foreign-key against.
--  * No drops of data, only of the one v1 read policy, which is replaced by a
--    stricter one in the same statement batch.
--
-- Tenant integrity is structural, not just a policy: composite foreign keys
-- (id, org_id) make it impossible for a target or a group membership to point
-- at a group/assignment/user of ANOTHER org, even from the service role.
--
-- RLS: org staff (org_admin, instructor) manage everything in their own org.
-- A student may read an assignment only if it is org-wide, targets them, targets
-- a group they belong to, or is their personal plan — and never an archived one.
-- Group, membership and target rows are staff-only; the API shows a student only
-- the names of the groups that target them.
--
-- Idempotent: safe to re-run (if-not-exists everywhere, constraints guarded).
-- ─────────────────────────────────────────────────────────────────────────────

-- ── 1. Groups ────────────────────────────────────────────────────────────────
create table if not exists public.org_groups (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references public.organizations(id) on delete cascade,
  name        text not null check (char_length(btrim(name)) between 1 and 80),
  description text check (description is null or char_length(description) <= 300),
  created_by  uuid references auth.users(id) on delete set null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  -- Target of the composite FKs below (tenant-pinned references).
  unique (id, org_id)
);

create unique index if not exists org_groups_org_name_uq on public.org_groups (org_id, lower(name));
create index if not exists org_groups_org_idx on public.org_groups (org_id);

drop trigger if exists org_groups_touch on public.org_groups;
create trigger org_groups_touch before update on public.org_groups
  for each row execute function public.touch_updated_at();

create table if not exists public.org_group_members (
  group_id  uuid not null,
  user_id   uuid not null,
  org_id    uuid not null,
  added_by  uuid references auth.users(id) on delete set null,
  added_at  timestamptz not null default now(),
  primary key (group_id, user_id),
  -- The group must be in the same org as the membership row…
  constraint org_group_members_group_fk foreign key (group_id, org_id)
    references public.org_groups (id, org_id) on delete cascade,
  -- …and so must the user. Leaving the org removes the membership.
  constraint org_group_members_member_fk foreign key (org_id, user_id)
    references public.org_members (org_id, user_id) on delete cascade
);

create index if not exists org_group_members_user_idx on public.org_group_members (user_id);
create index if not exists org_group_members_org_idx  on public.org_group_members (org_id);

-- ── 2. assignments — v2 columns ──────────────────────────────────────────────
alter table public.assignments add column if not exists audience         text        not null default 'org';
alter table public.assignments add column if not exists priority         smallint    not null default 2;
alter table public.assignments add column if not exists personal_user_id uuid;
alter table public.assignments add column if not exists archived_at      timestamptz;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'assignments_audience_chk') then
    alter table public.assignments add constraint assignments_audience_chk
      check (audience in ('org', 'targeted'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'assignments_priority_chk') then
    alter table public.assignments add constraint assignments_priority_chk
      check (priority between 1 and 3);
  end if;
  -- A personal plan is by definition targeted (at one person).
  if not exists (select 1 from pg_constraint where conname = 'assignments_personal_targeted_chk') then
    alter table public.assignments add constraint assignments_personal_targeted_chk
      check (personal_user_id is null or audience = 'targeted');
  end if;
  -- items stays a bounded array (v1 capped at 50; v2 at 100 in the API).
  if not exists (select 1 from pg_constraint where conname = 'assignments_items_array_chk') then
    alter table public.assignments add constraint assignments_items_array_chk
      check (jsonb_typeof(items) = 'array' and jsonb_array_length(items) <= 100);
  end if;
  -- Composite key so targets can be tenant-pinned to their assignment.
  if not exists (select 1 from pg_constraint where conname = 'assignments_id_org_uq') then
    alter table public.assignments add constraint assignments_id_org_uq unique (id, org_id);
  end if;
  -- The personal-plan owner must be a member of the plan's org; leaving the
  -- org removes their personal plan with them.
  if not exists (select 1 from pg_constraint where conname = 'assignments_personal_member_fk') then
    alter table public.assignments add constraint assignments_personal_member_fk
      foreign key (org_id, personal_user_id)
      references public.org_members (org_id, user_id) on delete cascade;
  end if;
end $$;

-- One personal plan per learner per org.
create unique index if not exists assignments_personal_uq
  on public.assignments (org_id, personal_user_id) where personal_user_id is not null;
create index if not exists assignments_org_active_idx
  on public.assignments (org_id) where archived_at is null;

-- ── 3. Targets ───────────────────────────────────────────────────────────────
create table if not exists public.assignment_targets (
  id            uuid primary key default gen_random_uuid(),
  assignment_id uuid not null,
  org_id        uuid not null,
  group_id      uuid,
  user_id       uuid,
  created_at    timestamptz not null default now(),
  constraint assignment_targets_one_chk check (num_nonnulls(group_id, user_id) = 1),
  constraint assignment_targets_assignment_fk foreign key (assignment_id, org_id)
    references public.assignments (id, org_id) on delete cascade,
  constraint assignment_targets_group_fk foreign key (group_id, org_id)
    references public.org_groups (id, org_id) on delete cascade,
  constraint assignment_targets_member_fk foreign key (org_id, user_id)
    references public.org_members (org_id, user_id) on delete cascade
);

create unique index if not exists assignment_targets_group_uq
  on public.assignment_targets (assignment_id, group_id) where group_id is not null;
create unique index if not exists assignment_targets_user_uq
  on public.assignment_targets (assignment_id, user_id) where user_id is not null;
create index if not exists assignment_targets_org_idx   on public.assignment_targets (org_id);
create index if not exists assignment_targets_user_idx  on public.assignment_targets (user_id) where user_id is not null;
create index if not exists assignment_targets_group_idx on public.assignment_targets (group_id) where group_id is not null;

-- ── 4. Recipient check (SECURITY DEFINER) ────────────────────────────────────
-- The student read policy on assignments needs to look at targets and group
-- membership, but both tables are staff-only under RLS — a plain subquery in
-- the policy would see zero rows for a student. This helper does that one
-- lookup with definer rights. It takes NO user parameter: it only ever answers
-- "is the CALLER a recipient of this assignment", so it cannot be used to probe
-- anyone else's group memberships.
create or replace function public.is_assignment_recipient(p_assignment uuid)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1
      from public.assignment_targets t
     where t.assignment_id = p_assignment
       and (
         t.user_id = auth.uid()
         or t.group_id in (select gm.group_id from public.org_group_members gm where gm.user_id = auth.uid())
       )
  )
$$;

revoke all on function public.is_assignment_recipient(uuid) from public;
revoke all on function public.is_assignment_recipient(uuid) from anon;
grant execute on function public.is_assignment_recipient(uuid) to authenticated;

-- ── 5. RLS ───────────────────────────────────────────────────────────────────
alter table public.org_groups         enable row level security;
alter table public.org_group_members  enable row level security;
alter table public.assignment_targets enable row level security;

-- assignments: replace the v1 "everyone in the org reads everything" policy.
drop policy if exists "assignments org read"    on public.assignments;
drop policy if exists "assignments member read" on public.assignments;
create policy "assignments member read" on public.assignments
  for select to authenticated using (
    org_id = public.current_org()
    and (
      public.current_org_role() in ('org_admin', 'instructor')
      or (
        archived_at is null
        and (
          (audience = 'org' and personal_user_id is null)
          or personal_user_id = auth.uid()
          or (audience = 'targeted' and public.is_assignment_recipient(id))
        )
      )
    )
  );
-- ("assignments staff write" from 0021 is unchanged: staff, own org only.)

-- Groups, memberships, targets: org staff only, pinned to their own org.
drop policy if exists "org_groups staff all" on public.org_groups;
create policy "org_groups staff all" on public.org_groups
  for all to authenticated
  using      (org_id = public.current_org() and public.current_org_role() in ('org_admin', 'instructor'))
  with check (org_id = public.current_org() and public.current_org_role() in ('org_admin', 'instructor'));

drop policy if exists "org_group_members staff all" on public.org_group_members;
create policy "org_group_members staff all" on public.org_group_members
  for all to authenticated
  using      (org_id = public.current_org() and public.current_org_role() in ('org_admin', 'instructor'))
  with check (org_id = public.current_org() and public.current_org_role() in ('org_admin', 'instructor'));

drop policy if exists "assignment_targets staff all" on public.assignment_targets;
create policy "assignment_targets staff all" on public.assignment_targets
  for all to authenticated
  using      (org_id = public.current_org() and public.current_org_role() in ('org_admin', 'instructor'))
  with check (org_id = public.current_org() and public.current_org_role() in ('org_admin', 'instructor'));

-- Revoke everything first (Supabase's default privileges also hand
-- authenticated TRUNCATE/REFERENCES/TRIGGER on new tables), then grant back only
-- the four DML verbs the policies above govern.
revoke all on public.org_groups         from anon, authenticated;
revoke all on public.org_group_members  from anon, authenticated;
revoke all on public.assignment_targets from anon, authenticated;
grant select, insert, update, delete on public.org_groups         to authenticated;
grant select, insert, update, delete on public.org_group_members  to authenticated;
grant select, insert, update, delete on public.assignment_targets to authenticated;

comment on table public.org_groups is
  'Named cohorts inside an org (e.g. "Tier-1 analysts") that learning plans can target. Staff-only under RLS.';
comment on table public.org_group_members is
  'Group membership. FK to org_members (org_id, user_id): leaving the org removes the membership.';
comment on table public.assignment_targets is
  'Recipients of a targeted learning plan: exactly one of group_id / user_id per row, tenant-pinned by composite FKs.';
comment on column public.assignments.audience is
  '''org'' = everyone in the org (v1 behaviour, the default); ''targeted'' = only assignment_targets recipients / the personal_user_id.';
comment on column public.assignments.personal_user_id is
  'Set on a learner''s single personal plan (unique per org). Null for group/org plans.';

-- Verification (see docs/SPEC-assignments-v2.md — run on STAGING):
--   set local role authenticated;
--   select set_config('request.jwt.claims', '{"sub":"<student>","org_id":"<org>","org_role":"student"}', true);
--   select id, title, audience from public.assignments;   -- only org-wide / own / own-group / own personal
--   select * from public.org_groups;                      -- zero rows for a student
