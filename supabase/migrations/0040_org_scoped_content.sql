-- 0040_org_scoped_content.sql
--
-- Per-org authored content (Phase 2). Adds an org dimension to the three global
-- content tables (0019) so an org admin can author lessons / quizzes / scenarios
-- that ONLY their own college sees, ALONGSIDE the global built-ins.
--
-- Additive model: org_id NULL = global/built-in (every existing row), non-null =
-- that one org's content. The read policy unions the two in a single clause, so
-- the existing publicContent.ts fetchers (which filter only on
-- status='published') return "global + this org" with NO client change — exactly
-- the shape org_resources (0038) already uses.
--
-- Writes stay SERVICE-ROLE ONLY, exactly like 0019: there is deliberately no
-- client INSERT/UPDATE/DELETE grant and no client write policy. The new
-- /api/org/content/[type] route (requireOrgAdmin) stamps org_id = the caller's
-- org, namespaces every id as `org:<org8>:…` so it can never collide with or
-- overwrite a global row, and re-asserts .eq('org_id', orgId) on read/update/
-- delete. Keeping writes off the client preserves 0019's "no client writes"
-- guarantee for the answer-bearing content jsonb.

do $$
declare t text;
begin
  foreach t in array array['content_scenarios','content_quizzes','content_lessons'] loop
    execute format(
      'alter table public.%I add column if not exists org_id uuid references public.organizations(id) on delete cascade', t);
    execute format(
      'create index if not exists %I on public.%I (org_id, status)', t || '_org_status_idx', t);
  end loop;
end $$;

-- Replace each global "published read" policy with the additive one.
drop policy if exists "content_scenarios published read" on public.content_scenarios;
drop policy if exists "content_quizzes published read"   on public.content_quizzes;
drop policy if exists "content_lessons published read"    on public.content_lessons;

create policy "content_scenarios read additive" on public.content_scenarios
  for select using (status = 'published' and (org_id is null or org_id = public.current_org()));
create policy "content_quizzes read additive" on public.content_quizzes
  for select using (status = 'published' and (org_id is null or org_id = public.current_org()));
create policy "content_lessons read additive" on public.content_lessons
  for select using (status = 'published' and (org_id is null or org_id = public.current_org()));

-- Grants unchanged from 0019 (SELECT to authenticated; nothing to anon; no
-- client write grant). Writes flow only through the service-role API route.
