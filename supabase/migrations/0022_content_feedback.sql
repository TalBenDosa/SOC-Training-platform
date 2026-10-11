-- ─────────────────────────────────────────────────────────────────────────────
-- 0022 — Content feedback ("report an issue")
-- ─────────────────────────────────────────────────────────────────────────────
-- There has been no way for a student to flag a wrong answer, a confusing
-- question, or a broken task. Every content defect found so far was found by
-- hand — the accuracy sweeps this platform has been through were expensive
-- precisely because the people hitting the defects had no way to say so.
-- A flag button turns every student into a quality sensor and makes each future
-- fix nearly free.
--
-- Design:
--  * `target_kind` + `target_id` are free text on purpose — the things being
--    reported (a room task, a scenario question, a quiz item, a dashboard
--    event) live in the TypeScript corpus, not the DB, so there is nothing to
--    foreign-key against. `context` carries whatever else pins the report down
--    (room id, task index, the question text as displayed).
--  * `org_id` is captured so a college's own staff can see their students'
--    reports, and so reports survive as evidence of where a cohort struggled.
--  * `status` lets Tal triage without deleting: new → triaged → resolved/wontfix.
--
-- RLS: a student may INSERT their own report and read only their own. Org staff
-- read their org's. Platform admins read everything (that policy is expressed
-- via profiles.role = 'admin' rather than a JWT claim, matching how /admin is
-- gated elsewhere in the app).
-- ─────────────────────────────────────────────────────────────────────────────

do $$
begin
  if not exists (select 1 from pg_type where typname = 'feedback_status') then
    create type public.feedback_status as enum ('new', 'triaged', 'resolved', 'wontfix');
  end if;
end $$;

create table if not exists public.content_feedback (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid references auth.users(id) on delete set null,
  org_id      uuid references public.organizations(id) on delete set null,
  target_kind text not null,                 -- 'room_task' | 'scenario' | 'quiz' | 'other'
  target_id   text not null,                 -- room id / scenario slug / quiz id
  context     jsonb not null default '{}'::jsonb,
  message     text not null,
  status      public.feedback_status not null default 'new',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create index if not exists content_feedback_status_idx  on public.content_feedback(status, created_at desc);
create index if not exists content_feedback_target_idx  on public.content_feedback(target_kind, target_id);
create index if not exists content_feedback_org_idx     on public.content_feedback(org_id);

drop trigger if exists content_feedback_touch on public.content_feedback;
create trigger content_feedback_touch before update on public.content_feedback
  for each row execute function public.touch_updated_at();

alter table public.content_feedback enable row level security;

-- Students: file a report as themselves, and read back only their own.
drop policy if exists "content_feedback insert own" on public.content_feedback;
create policy "content_feedback insert own" on public.content_feedback
  for insert with check (user_id = auth.uid());

drop policy if exists "content_feedback read own" on public.content_feedback;
create policy "content_feedback read own" on public.content_feedback
  for select using (user_id = auth.uid());

-- Org staff: read their own org's reports (cohort friction is their signal too).
drop policy if exists "content_feedback org staff read" on public.content_feedback;
create policy "content_feedback org staff read" on public.content_feedback
  for select using (
    org_id = public.current_org()
    and public.current_org_role() in ('org_admin','instructor')
  );

-- Platform admin: full read/triage across every org. Matches how /admin is
-- gated in the app (profiles.role = 'admin'), not an org-scoped claim.
drop policy if exists "content_feedback platform admin" on public.content_feedback;
create policy "content_feedback platform admin" on public.content_feedback
  for all
  using      (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'))
  with check (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'));

revoke all on public.content_feedback from anon;
grant select, insert on public.content_feedback to authenticated;
grant update on public.content_feedback to authenticated;  -- gated to admins by RLS above

comment on table public.content_feedback is
  'Student-filed reports of wrong/confusing/broken content. Triaged by the platform admin; readable by the filer and by their org staff.';
