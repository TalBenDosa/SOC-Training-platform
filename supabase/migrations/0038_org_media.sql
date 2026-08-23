-- HACK THE SOC :: 0038 — per-org media resources ("College Materials")
-- ---------------------------------------------------------------------------
-- Phase 1 of per-org content control (docs plan). Lets an org-admin upload
-- unique presentations (PDF/PPTX) and videos that appear ONLY in their own
-- environment — "environmental uniqueness". This is the platform's first file
-- upload/storage capability.
--
-- Media is deliberately NOT global (unlike the content_* tables): the whole
-- point is per-college uniqueness, so there is no org_id-NULL "global" row here.
-- The row is a POINTER to an object in the private `org-media` Storage bucket;
-- delivery is via short-lived signed URLs minted server-side after an
-- org-membership re-assertion. Writes go through the service-role client behind
-- requireOrgAdmin (same posture as 0019/0021); no client write path exists.
--
-- RLS mirrors the assignments pattern (0021): read = own org + published,
-- write = own-org staff. Reuses the admin_content_status enum (0019) and the
-- generic touch_updated_at() trigger (0002).

create table if not exists public.org_resources (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid not null references public.organizations(id) on delete cascade,
  kind         text not null check (kind in ('pdf','pptx','video')),
  title        text not null,
  storage_key  text not null,                          -- '<org_id>/<kind>/<uuid>.<ext>'
  mime         text not null,
  size_bytes   bigint not null,
  status       public.admin_content_status not null default 'draft',
  created_by   uuid references auth.users(id) on delete set null,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create index if not exists org_resources_org_status_idx on public.org_resources(org_id, status);

drop trigger if exists org_resources_touch on public.org_resources;
create trigger org_resources_touch before update on public.org_resources
  for each row execute function public.touch_updated_at();

alter table public.org_resources enable row level security;

-- Read: any member of the org, but only PUBLISHED materials (drafts are staff-only,
-- read through the service-role admin API). Not global — scoped to current_org().
drop policy if exists "org_resources org read" on public.org_resources;
create policy "org_resources org read" on public.org_resources
  for select using (org_id = public.current_org() and status = 'published');

-- Write: org staff only, pinned to their OWN org (WITH CHECK) so one college
-- cannot create materials inside another. Service role (the upload API) bypasses
-- this, and re-asserts org_id in code — this policy is defense-in-depth.
drop policy if exists "org_resources staff write" on public.org_resources;
create policy "org_resources staff write" on public.org_resources
  for all
  using      (org_id = public.current_org() and public.current_org_role() in ('org_admin','instructor'))
  with check (org_id = public.current_org() and public.current_org_role() in ('org_admin','instructor'));

revoke all on public.org_resources from anon;

-- ── Private Storage bucket ───────────────────────────────────────────────────
-- Not public: objects are reachable only via server-minted signed URLs. No
-- storage.objects policy is added, so the anon/authenticated roles have no
-- object access at all (default-deny) — only the service role (the API) can
-- read/write, exactly the isolation we want. file_size_limit + allowed MIME
-- types are a second guard on top of the API's magic-byte checks.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'org-media', 'org-media', false, 209715200,   -- 200 MB hard cap (video); API enforces tighter per-kind
  array[
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'video/mp4', 'video/webm'
  ]
)
on conflict (id) do nothing;

-- Verification:
--   select id, name, public from storage.buckets where id = 'org-media';
--   -- as org-admin A: insert a row with org_id=A → ok; select from org B → 0 rows.
