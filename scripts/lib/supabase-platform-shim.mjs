// Minimal stand-ins for the Supabase platform schemas the migrations touch
// (storage, pg_cron, realtime), so the PGlite e2e gates can apply EVERY migration.
// They only need to exist with the right shape; nothing here is exercised as a feature.
// Without them `npm run test:e2e` / `test:tenancy` crashed at 0038 (storage.buckets)
// and never reached the later migrations.
export const PLATFORM_SHIM = `
create schema if not exists storage;
create table if not exists storage.buckets (
  id text primary key, name text, owner uuid, public boolean default false,
  file_size_limit bigint, allowed_mime_types text[], created_at timestamptz default now(), updated_at timestamptz default now()
);
create table if not exists storage.objects (
  id uuid primary key default gen_random_uuid(), bucket_id text references storage.buckets(id),
  name text, owner uuid, metadata jsonb, created_at timestamptz default now(), updated_at timestamptz default now()
);

create schema if not exists cron;
create table if not exists cron.job (
  jobid bigserial primary key, schedule text, command text, nodename text default 'localhost',
  nodeport int default 5432, database text default 'postgres', username text default 'postgres',
  active boolean default true, jobname text unique
);
create table if not exists cron.job_run_details (
  jobid bigint, runid bigserial primary key, job_pid int, database text, username text, command text,
  status text, return_message text, start_time timestamptz, end_time timestamptz
);
create or replace function cron.schedule(p_jobname text, p_schedule text, p_command text) returns bigint
  language sql as $f$
    insert into cron.job (jobname, schedule, command) values (p_jobname, p_schedule, p_command)
    on conflict (jobname) do update set schedule = excluded.schedule, command = excluded.command
    returning jobid
  $f$;
create or replace function cron.schedule(p_schedule text, p_command text) returns bigint
  language sql as $f$ insert into cron.job (schedule, command) values (p_schedule, p_command) returning jobid $f$;
create or replace function cron.unschedule(p_jobname text) returns boolean
  language sql as $f$ with d as (delete from cron.job where jobname = p_jobname returning 1) select exists(select 1 from d) $f$;
create or replace function cron.unschedule(p_jobid bigint) returns boolean
  language sql as $f$ with d as (delete from cron.job where jobid = p_jobid returning 1) select exists(select 1 from d) $f$;
create or replace function cron.alter_job(job_id bigint, schedule text default null, command text default null,
  database text default null, username text default null, active boolean default null) returns void
  language sql as $f$
    update cron.job set schedule = coalesce(alter_job.schedule, cron.job.schedule),
      command = coalesce(alter_job.command, cron.job.command), active = coalesce(alter_job.active, cron.job.active)
    where jobid = job_id
  $f$;

create schema if not exists realtime;
create table if not exists realtime.messages (
  id bigserial primary key, topic text, extension text, payload jsonb, event text, private boolean default false,
  inserted_at timestamptz default now(), updated_at timestamptz default now()
);
create or replace function realtime.topic() returns text
  language sql stable as $f$ select nullif(current_setting('realtime.topic', true), '') $f$;
create or replace function realtime.send(payload jsonb, event text, topic text, private boolean default true) returns void
  language sql as $f$ insert into realtime.messages (topic, payload, event, private) values (topic, payload, event, private) $f$;
grant usage on schema storage, cron, realtime to anon, authenticated, service_role;
`;
