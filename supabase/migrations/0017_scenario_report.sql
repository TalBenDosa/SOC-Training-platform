-- HACK THE SOC :: 0017 — persist the analyst's written scenario report
-- ===========================================================================
-- Until now scenario_history stored only score/xp/time — the analyst's actual
-- written deliverable (verdict, reasoning, notes, findings, rubric breakdown)
-- was graded and then thrown away. For a TRAINING platform that is the wrong
-- thing to discard: a learner can't review how they wrote past reports, and an
-- instructor (B2B org-admin console) can't see real work, only a number.
--
-- This adds a single nullable jsonb column. Purely additive: existing rows get
-- NULL, and the app treats NULL/absent as "no saved report" (older records and
-- guests still render). RLS is unchanged — the existing per-user/org policies on
-- scenario_history already govern who can read the row, and therefore the report.
--
-- SAFETY: idempotent, no data loss, no lock of consequence (ADD COLUMN with a
-- NULL default is metadata-only in Postgres). Run any time.
-- ===========================================================================

alter table public.scenario_history
  add column if not exists report jsonb;

-- Verify: select column_name from information_schema.columns
--         where table_name='scenario_history' and column_name='report';   -- 1 row
