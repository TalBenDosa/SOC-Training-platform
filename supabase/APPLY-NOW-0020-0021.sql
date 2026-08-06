-- ═══════════════════════════════════════════════════════════════════════════
-- PASTE-AND-RUN — migrations 0020 + 0021 (SEV-1)
-- ═══════════════════════════════════════════════════════════════════════════
-- Both migrations combined into one script. Safe to run more than once
-- (every statement is `if not exists` / `or replace` / `drop ... if exists`),
-- so re-running after a partial failure is fine.
--
-- Where: Supabase dashboard → project "Hack The SOC Real" → SQL Editor → paste → Run.
-- Supabase will warn "destructive operations detected" — that's the
-- `drop trigger/policy if exists` guards, which only remove objects this same
-- script immediately recreates. No table or user data is dropped.
--
-- Until this runs:
--   · /manage shows no Assignments card (the API 500s on a missing table)
--   · the super-admin Contract editor fails on save
--   · everything else — including the new cohort analytics and CSV export —
--     works, because those need no new schema.
--
-- Verification query is at the bottom.
-- ═══════════════════════════════════════════════════════════════════════════


-- ── 0020 — Contract record on organizations ────────────────────────────────
-- A commercial RECORD (plan, seats sold, price, PO, signed date, notes), not a
-- billing engine: it charges nobody and gates nothing. Access is still governed
-- by seat_limit / expires_at.
--
-- NOTE: `organizations` already has an "organizations read own" RLS policy, so
-- a college CAN read its own contract blob. That's intentional (they're their
-- own terms) — but it means nothing internal-only (margins, other tenants'
-- pricing) may be stored here.

alter table public.organizations
  add column if not exists contract jsonb not null default '{}'::jsonb;

comment on column public.organizations.contract is
  'Commercial record for this org (manual, super-admin authored): plan, seats_purchased, price, currency, po_number, signed_at, notes. Not a billing engine. Readable by the org itself under the existing "organizations read own" RLS policy.';


-- ── 0021 — Assignments (instructor-directed coursework) ────────────────────
-- `items` is jsonb ({kind:'room'|'scenario', id}) because the referenced ids
-- live in the TypeScript content corpus, not the DB — a join table would buy
-- referential integrity it cannot actually enforce.
--
-- There is deliberately NO submissions table: completion is derived from
-- room_progress / scenario_history, so work finished last week counts the
-- moment it's assigned, and there's one source of truth for "did they do it".

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

-- Read: any member of the org — students included, it's their homework.
drop policy if exists "assignments org read" on public.assignments;
create policy "assignments org read" on public.assignments
  for select using (org_id = public.current_org());

-- Write: org staff only, pinned to their OWN org by the WITH CHECK so an
-- instructor cannot create coursework inside another college.
drop policy if exists "assignments staff write" on public.assignments;
create policy "assignments staff write" on public.assignments
  for all
  using      (org_id = public.current_org() and public.current_org_role() in ('org_admin','instructor'))
  with check (org_id = public.current_org() and public.current_org_role() in ('org_admin','instructor'));

revoke all on public.assignments from anon;
grant select, insert, update, delete on public.assignments to authenticated;

comment on table public.assignments is
  'Instructor-set coursework for an org: a titled list of rooms/scenarios with an optional due date. Progress is DERIVED from room_progress/scenario_history — there is intentionally no submissions table.';


-- ═══════════════════════════════════════════════════════════════════════════
-- VERIFY — run this after the above; expect one row, all three columns true/2.
-- ═══════════════════════════════════════════════════════════════════════════
select
  (select count(*) from information_schema.columns
     where table_schema = 'public' and table_name = 'organizations'
       and column_name = 'contract')                                  = 1  as contract_column_added,
  (select relrowsecurity from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relname = 'assignments')              as assignments_rls_on,
  (select count(*) from pg_policies where tablename = 'assignments')        as assignments_policy_count;
