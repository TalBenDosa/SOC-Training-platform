-- 0043_org_rooms.sql
--
-- Per-org authored Learning Rooms (Phase 3). Same two-projection split as
-- scenarios (0040/0041), because a room's task answers (question answer index,
-- flag value, checkpoint answer, verdict, correct order, matching pairs) ARE the
-- exercise and content_rooms is RLS-readable by org members.
--
--   content_rooms       — CLIENT-SAFE projection: room meta + tasks with every
--                         answer field stripped. Additive RLS (global built-ins
--                         are static/compiled-in, so every row here is org-owned;
--                         org_id is still nullable + the union clause is kept for
--                         symmetry with the other content tables).
--   content_room_keys   — the answer key, in a table the browser cannot read
--                         (RLS on, no policy, revoke all → service-role only).
--
-- The resolver (src/lib/rooms/resolve.ts) recombines the two in server memory
-- into a full Room and feeds the existing server-side gradeTask unchanged; the
-- play page then runs sanitizeRoom over it exactly as it does for static rooms.

create table if not exists public.content_rooms (
  id          text primary key,
  org_id      uuid references public.organizations(id) on delete cascade,
  status      public.admin_content_status not null default 'draft',
  content     jsonb not null,
  title       text generated always as (content->>'title') stored,
  created_by  uuid references auth.users(id) on delete set null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists content_rooms_org_status_idx on public.content_rooms (org_id, status);

drop trigger if exists content_rooms_touch on public.content_rooms;
create trigger content_rooms_touch before update on public.content_rooms
  for each row execute function public.touch_updated_at();

alter table public.content_rooms enable row level security;
drop policy if exists "content_rooms read additive" on public.content_rooms;
create policy "content_rooms read additive" on public.content_rooms
  for select using (status = 'published' and (org_id is null or org_id = public.current_org()));

-- Writes are service-role only (no client write grant), exactly like 0019/0040.
revoke all on public.content_rooms from anon;
grant select on public.content_rooms to authenticated;

-- ── zero-grant answer key ────────────────────────────────────────────────────
create table if not exists public.content_room_keys (
  id          text primary key references public.content_rooms(id) on delete cascade,
  org_id      uuid references public.organizations(id) on delete cascade,
  answer_key  jsonb not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

drop trigger if exists content_room_keys_touch on public.content_room_keys;
create trigger content_room_keys_touch before update on public.content_room_keys
  for each row execute function public.touch_updated_at();

-- Deny-by-default: RLS on, no policy, and no client grant.
alter table public.content_room_keys enable row level security;
revoke all on public.content_room_keys from anon, authenticated;
