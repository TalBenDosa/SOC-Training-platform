-- ─────────────────────────────────────────────────────────────────────────────
-- 0019 — Durable storage for admin-authored content (scenarios/quizzes/lessons)
-- ─────────────────────────────────────────────────────────────────────────────
-- Content generated via /admin's "Generate with AI" tools (scenarios, quizzes,
-- lessons) was persisted ONLY to the admin's own browser localStorage
-- (published_scenarios / generated_quizzes / generated_lessons). Two real
-- problems, not one:
--   1. Durability — a browser-data clear or device switch loses it permanently.
--   2. Visibility — localStorage is per-browser, so /learn, /scenarios and
--      /quizzes (which read the SAME keys directly, client-side) only ever see
--      it on the admin's own device. A real student, on their own browser, has
--      never actually seen any content published through this tool — the
--      feature has been non-functional for its actual purpose since it shipped.
--
-- Fix: three durable tables, one per content type. Content itself is stored as
-- jsonb (the shapes already vary per type — events[] vs questions[] vs
-- sections[] — and normalising them into relational columns would be premature
-- structure for a hand-authored admin tool). `title` is a generated column so
-- the admin list/search views don't need to decode jsonb per row.
--
-- Access pattern matches the platform's existing convention (org/members,
-- superadmin/orgs): writes go exclusively through admin API routes using the
-- SERVICE-ROLE client after an application-level requireAdmin() gate — there is
-- no RLS policy permitting client-side writes. The one RLS policy that exists
-- is the read path for real students: any authenticated user may SELECT rows
-- with status = 'published'. Admin reads (including drafts) go through the
-- service-role client in the admin API, which bypasses RLS entirely.
-- ─────────────────────────────────────────────────────────────────────────────

do $$
begin
  if not exists (select 1 from pg_type where typname = 'admin_content_status') then
    create type public.admin_content_status as enum ('draft', 'published');
  end if;
end $$;

create table if not exists public.content_scenarios (
  id          text primary key,
  status      public.admin_content_status not null default 'draft',
  content     jsonb not null,
  title       text generated always as (content->>'title') stored,
  created_by  uuid references auth.users(id) on delete set null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.content_quizzes (
  id          text primary key,
  status      public.admin_content_status not null default 'draft',
  content     jsonb not null,
  title       text generated always as (content->>'title') stored,
  created_by  uuid references auth.users(id) on delete set null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.content_lessons (
  id          text primary key,
  status      public.admin_content_status not null default 'draft',
  content     jsonb not null,
  title       text generated always as (content->>'title') stored,
  created_by  uuid references auth.users(id) on delete set null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create index if not exists content_scenarios_status_idx on public.content_scenarios(status);
create index if not exists content_quizzes_status_idx   on public.content_quizzes(status);
create index if not exists content_lessons_status_idx   on public.content_lessons(status);

-- Reuses the generic public.touch_updated_at() trigger function already
-- defined in 0002_app_progress.sql — no need for a per-table duplicate.
drop trigger if exists content_scenarios_touch on public.content_scenarios;
create trigger content_scenarios_touch before update on public.content_scenarios
  for each row execute function public.touch_updated_at();

drop trigger if exists content_quizzes_touch on public.content_quizzes;
create trigger content_quizzes_touch before update on public.content_quizzes
  for each row execute function public.touch_updated_at();

drop trigger if exists content_lessons_touch on public.content_lessons;
create trigger content_lessons_touch before update on public.content_lessons
  for each row execute function public.touch_updated_at();

alter table public.content_scenarios enable row level security;
alter table public.content_quizzes   enable row level security;
alter table public.content_lessons   enable row level security;

drop policy if exists "content_scenarios published read" on public.content_scenarios;
create policy "content_scenarios published read" on public.content_scenarios
  for select using (status = 'published');

drop policy if exists "content_quizzes published read" on public.content_quizzes;
create policy "content_quizzes published read" on public.content_quizzes
  for select using (status = 'published');

drop policy if exists "content_lessons published read" on public.content_lessons;
create policy "content_lessons published read" on public.content_lessons
  for select using (status = 'published');

-- No insert/update/delete policy on any of the three tables: writes are
-- exclusively via /api/admin/content/* using the service-role client, gated by
-- requireAdmin(). This is intentional, not an oversight.

revoke all on public.content_scenarios, public.content_quizzes, public.content_lessons from anon;
grant select on public.content_scenarios, public.content_quizzes, public.content_lessons to authenticated;

comment on table public.content_scenarios is 'Admin-authored/AI-generated scenarios, durable replacement for the old published_scenarios localStorage key. Writes via /api/admin/content/scenarios only.';
comment on table public.content_quizzes is 'Admin-authored/AI-generated quizzes, durable replacement for the old generated_quizzes localStorage key. Writes via /api/admin/content/quizzes only.';
comment on table public.content_lessons is 'Admin-authored/AI-generated lessons, durable replacement for the old generated_lessons localStorage key. Writes via /api/admin/content/lessons only.';
