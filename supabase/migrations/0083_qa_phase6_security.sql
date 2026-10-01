-- 0083_qa_phase6_security.sql — QA phase 6 (security) database fixes.
--
-- SEC-05  revoke_user_sessions(): end every refresh session of a user whose access
--         was just taken away (removed from an org, deactivated). The app calls it
--         after the membership change; service-role only.

-- ── SEC-05 ── revoke a user's sessions ──────────────────────────────────────────
create or replace function public.revoke_user_sessions(p_user uuid)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  n integer;
begin
  -- auth.refresh_tokens.session_id cascades, so no new access token can be minted.
  delete from auth.sessions where user_id = p_user;
  get diagnostics n = row_count;
  return n;
end;
$$;
revoke execute on function public.revoke_user_sessions(uuid) from public, anon, authenticated;
grant  execute on function public.revoke_user_sessions(uuid) to service_role;
