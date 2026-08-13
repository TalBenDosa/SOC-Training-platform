-- HACK THE SOC :: 0034 — close write-side forgery gaps (security review 2026-08)
-- ===========================================================================
-- Two findings from the pre-production security review (docs/SECURITY-REVIEW-2026-08.md):
--
--   M3 — profiles.xp_offset was client-writable. `revoke update (xp,level)`
--        (0008:105) froze xp/level, and the 0016 guard trigger froze
--        id/role/org_id/is_platform_admin — but NOBODY froze xp_offset. Since
--        recompute_user_xp() computes xp = xp_offset + Σ(xp_earned) with no
--        upper bound (0008:55) and 0025 bounds only the per-row xp_earned, a
--        signed-in user could `update profiles set xp_offset = 9e6 where
--        id = auth.uid()`, then trigger a recompute, and inflate their XP /
--        rank without limit — bypassing the 0025 mitigation entirely.
--        Same class covers the cosmetic columns rank / streak_days /
--        last_nudged_at, which were likewise neither revoked nor guarded.
--
--   L1 — content_feedback, task_attempts and account_deletion_requests each
--        granted INSERT to `authenticated` with a WITH CHECK that pinned only
--        user_id (never org_id / correct). Every REAL write to these tables
--        goes through the service role (the feedback, submit and account
--        routes), so the client INSERT grant is pure attack surface: it let a
--        user forge task_attempts.correct = true history the instructor console
--        reads, or inject an attacker-controlled content_feedback row stamped
--        with another org's id.
--
-- SAFETY (verified against the codebase AND the live grant model before writing):
--   * xp_offset has NO legitimate authenticated-context writer — recompute_user_xp
--     READS it, never writes it; it is otherwise only seeded once (0008) or set by
--     the service role. So freezing it in the guard trigger cannot fight any real
--     flow, and the trigger reverts it whether or not a grant exists.
--   * No browser/client code inserts into the three L1 tables — all inserts are
--     service-role route writes, which a `revoke insert … from authenticated`
--     does not touch. So those grants are dead client surface; removing them is safe.
--
-- WHY THE GUARD TRIGGER, NOT A COLUMN REVOKE (learned during rollout):
--   `authenticated` holds a TABLE-level UPDATE grant on profiles (needed for the
--   "profiles self update" policy). In Postgres a column-level `REVOKE UPDATE(col)`
--   does NOT subtract from a table-level grant — has_column_privilege() stays true
--   — so a column revoke here would be a no-op that only LOOKS protective. The
--   guard trigger is the mechanism that actually works: it rewrites new.col :=
--   old.col for every user-driven (auth.uid() not null) UPDATE, exactly as it
--   already does for id/role/org_id/is_platform_admin. The service role and the
--   definer recompute path run with auth.uid() = null, so they are unaffected.
--   (rank / streak_days / last_nudged_at are left as-is: rank is trigger-derived
--   from xp and a forged value is overwritten on the next xp change; all three are
--   cosmetic/Low and not worth the trigger-ordering risk. Tracked as residual I3.)

-- ── M3 — freeze xp_offset in the guard trigger (the control that actually works) ─
create or replace function public.guard_profile_privileged_columns()
returns trigger
language plpgsql set search_path = public
as $$
begin
  if auth.uid() is not null then
    new.id                := old.id;
    new.role              := old.role;
    new.org_id            := old.org_id;
    new.is_platform_admin := old.is_platform_admin;
    new.xp_offset         := old.xp_offset;
  end if;
  return new;
end;
$$;

-- ── L1 — remove the unnecessary client INSERT grants ─────────────────────────
-- All real writes to these tables are service-role route writes, which are
-- unaffected by a revoke from the client roles. This removes the ability to
-- forge rows with an arbitrary org_id / correct flag directly via PostgREST.
revoke insert on public.content_feedback        from anon, authenticated;
revoke insert on public.task_attempts           from anon, authenticated;
revoke insert on public.account_deletion_requests from anon, authenticated;

-- ── Verify (run manually after applying) ─────────────────────────────────────
-- As a signed-in NON-admin user of some org:
--   update public.profiles set xp_offset = 999999 where id = auth.uid();
--     -- expect: statement succeeds but is a NO-OP — the guard trigger reverts
--     --   xp_offset to its old value; `select xp_offset` is unchanged.
--   insert into public.task_attempts (user_id, org_id, room_id, task_id, correct)
--     values (auth.uid(), public.current_org(), 'x', 'y', true);
--     -- expect: ERROR permission denied for table task_attempts
-- Structural checks (any connection):
--   select position('new.xp_offset' in
--     pg_get_functiondef('public.guard_profile_privileged_columns()'::regprocedure)) > 0;  -- t
--   select has_table_privilege('authenticated','public.task_attempts','INSERT');            -- f
--   select has_table_privilege('service_role','public.task_attempts','INSERT');             -- t
-- Legit paths still work (run as the app does, via the service role):
--   completing a room still recomputes xp/level/rank; the submit route still
--   records task_attempts; the feedback and deletion routes still insert.
