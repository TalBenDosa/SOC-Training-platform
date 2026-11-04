-- 0102: Learning Rooms are OPEN by default; the college admin decides whether to lock them (Tal, 2026-11-04).
--
-- Until now every room was locked until the learner passed its prerequisites, and the only way
-- out was the super-admin-only bypass all_rooms_unlocked (0036). Tal's rule: every room is open,
-- and locking (prerequisite order) is an admin decision per organization.
--
-- rooms_locked = false (default): every room is open to this org's members; the rooms page still
--   shows them by level and recommends the next room in prerequisite order.
-- rooms_locked = true: a room unlocks only after its prerequisite rooms are passed.
-- all_rooms_unlocked (0036) keeps working as an override: true always means open.
--
-- Additive, so every existing organization becomes "open" with no data change. Written by the
-- app routes with the service role (org admin: /api/org/settings, super-admin:
-- /api/superadmin/orgs/[id]); organizations stays readable by its own members under the existing RLS.
--
-- Verify: select column_name, data_type, is_nullable, column_default from information_schema.columns
--          where table_schema = 'public' and table_name = 'organizations' and column_name = 'rooms_locked';
--         -> boolean, NO, false

alter table public.organizations
  add column if not exists rooms_locked boolean not null default false;

comment on column public.organizations.rooms_locked is
  'When true, a Learning Room unlocks for this org''s members only after its prerequisite rooms are passed. Default false: every room is open. Set by the org admin (/manage) or the super-admin. all_rooms_unlocked = true overrides it.';
