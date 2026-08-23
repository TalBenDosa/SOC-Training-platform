-- 0044_org_companies.sql
--
-- Per-org authored LIVE-FEED environments (Phase 3b). An org authors a custom
-- "company" — its profile, its benign background noise, and one attack story —
-- that its students practise on in the SOC Dashboard live feed, alongside the
-- global built-in companies.
--
-- Unlike scenarios/rooms, this needs NO zero-grant answer-key split, and here is
-- why: the live feed never client-scores detection (there is no "is this bad?"
-- gate). The one graded artifact is the incident report, which is graded
-- server-side (/api/dashboard/incident-report) against ground truth
-- (attack title / MITRE / real indicators) that the CLIENT derives from the
-- story's own events and sends up. The static AttackStory already ships title +
-- mitre + expected_verdict into the browser bundle today. So an org story in a
-- single RLS-readable table is exact parity with the existing static model — a
-- split would hide nothing that isn't already client-visible by design.
--
-- content_companies.content = the whole authored environment:
--   { kind:"authored", id, name, industry, tagline, description, size, hq,
--     sources:[LogSource...], benignEvents:[TelemetryEvent...],
--     story:{ title, mitre:[...], events:[TelemetryEvent...] } }
--
-- Additive RLS + service-role-only writes, exactly like content_scenarios (0040).

create table if not exists public.content_companies (
  id          text primary key,
  org_id      uuid references public.organizations(id) on delete cascade,
  status      public.admin_content_status not null default 'draft',
  content     jsonb not null,
  title       text generated always as (content->>'name') stored,
  created_by  uuid references auth.users(id) on delete set null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists content_companies_org_status_idx on public.content_companies (org_id, status);

drop trigger if exists content_companies_touch on public.content_companies;
create trigger content_companies_touch before update on public.content_companies
  for each row execute function public.touch_updated_at();

alter table public.content_companies enable row level security;
drop policy if exists "content_companies read additive" on public.content_companies;
create policy "content_companies read additive" on public.content_companies
  for select using (status = 'published' and (org_id is null or org_id = public.current_org()));

-- Explicitly strip the broad default-privilege grants and re-grant SELECT only,
-- so client writes are blocked at the grant level too (not just by the missing
-- write RLS policy). Writes flow only through the service-role API route.
revoke all on public.content_companies from anon, authenticated;
grant select on public.content_companies to authenticated;
