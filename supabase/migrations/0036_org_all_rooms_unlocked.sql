-- HACK THE SOC :: 0036 — per-org "all rooms unlocked" override
-- ---------------------------------------------------------------------------
-- Room locking is per-LEARNER and prerequisite-based (isRoomLocked in
-- src/lib/rooms/recommend.ts): a room is locked until the learner has completed
-- its prerequisites. There was no way for an org to opt its members out of that
-- gating — some clients (e.g. an evaluation/pilot cohort that wants to explore
-- the whole catalogue freely) need every room open from day one.
--
-- This adds an OPT-IN per-org flag. Default false, so every existing org keeps
-- the pedagogical prerequisite scaffolding unchanged. When true, the client
-- (via /api/org/branding → useBranding) treats every room as unlocked for that
-- org's members only — no other org is affected.
--
-- Access: `organizations` already has RLS (0011) — a member reads only their own
-- org row. Reading this flag is fine (it's the org's own setting). Writes stay
-- super-admin-only via the service-role client; no client write policy exists.

alter table public.organizations
  add column if not exists all_rooms_unlocked boolean not null default false;

comment on column public.organizations.all_rooms_unlocked is
  'When true, this org''s members see every Learning Room unlocked regardless of prerequisites (client-side gate bypass via /api/org/branding). Default false keeps the normal per-learner prerequisite gating. Super-admin sets this per org.';

-- Enabling it for a specific org (e.g. the National Cyber Directorate) is a
-- data change done separately once the exact org row is identified, e.g.:
--   update public.organizations set all_rooms_unlocked = true
--    where name ilike '%סייבר%' or slug = '<their-slug>';
-- (Confirm with a SELECT first — this is not hardcoded here so the migration
--  stays safe to run on any deployment.)

-- Verification:
--   select id, name, slug, all_rooms_unlocked from public.organizations;
