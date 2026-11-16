-- HACK THE SOC :: 0111 — Lesson Library lessons a learner has studied
-- ---------------------------------------------------------------------------
-- Recommended Tracks (/tracks) count a Lesson Library lesson as studied when the learner
-- reads it to the last page or ticks it on the track. Until now that mark lived only in
-- the browser, so it did not follow the learner to another computer. This table keeps it
-- on the server: one row per learner, organisation and lesson.
--
-- Written ONLY by the server (POST /api/me/library-reads, which checks the lesson is a
-- built-in library lesson) through set_library_read(); read by
--   - the learner (their own rows, RLS),
--   - the same route, pinned to the learner's CURRENT organisation (iron rule: nothing from
--     one organisation or environment shows in another).
--
-- Org isolation: org_id references organizations with ON DELETE CASCADE, so purge_org
-- removes these rows; a user deletion cascades from auth.users.
--
-- NON-DESTRUCTIVE: a new, empty table and one function. Idempotent.

create table if not exists public.library_reads (
  id          bigint generated always as identity primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  org_id      uuid references public.organizations(id) on delete cascade,
  lesson_id   text not null check (char_length(lesson_id) between 1 and 200),
  read_at     timestamptz not null default now()
);
-- One mark per learner, organisation (or none) and lesson.
create unique index if not exists library_reads_unique_idx
  on public.library_reads (user_id, (coalesce(org_id, '00000000-0000-0000-0000-000000000000'::uuid)), lesson_id);
create index if not exists library_reads_org_idx on public.library_reads (org_id);

alter table public.library_reads enable row level security;
drop policy if exists library_reads_read_own on public.library_reads;
create policy library_reads_read_own on public.library_reads
  for select to authenticated using (user_id = auth.uid());
revoke all on public.library_reads from anon;
revoke insert, update, delete on public.library_reads from authenticated;
grant select on public.library_reads to authenticated;
grant select, insert, delete on public.library_reads to service_role;

-- Marks (p_studied = true) or unmarks one lesson for one learner in one organisation.
create or replace function public.set_library_read(
  p_user uuid, p_org uuid, p_lesson text, p_studied boolean
) returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_user is null or p_lesson is null or char_length(p_lesson) not between 1 and 200 then
    raise exception 'invalid lesson';
  end if;
  if p_studied then
    insert into public.library_reads (user_id, org_id, lesson_id)
    values (p_user, p_org, p_lesson)
    on conflict (user_id, (coalesce(org_id, '00000000-0000-0000-0000-000000000000'::uuid)), lesson_id) do nothing;
  else
    delete from public.library_reads
    where user_id = p_user and org_id is not distinct from p_org and lesson_id = p_lesson;
  end if;
end;
$$;

revoke all on function public.set_library_read(uuid, uuid, text, boolean) from public, anon, authenticated;
grant execute on function public.set_library_read(uuid, uuid, text, boolean) to service_role;
