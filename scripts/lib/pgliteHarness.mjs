// Shared PGlite harness: every migration in supabase/migrations applied to an
// in-memory Postgres behind thin Supabase shims (auth, storage, realtime, cron).
// Lets DB-level behaviour (RLS, grants, triggers, RPCs) be tested locally with
// no Docker and no remote database.
import { PGlite } from "@electric-sql/pglite";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const MIG = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "supabase", "migrations");

export const SHIM = `
create schema if not exists auth;
create table if not exists auth.users (id uuid primary key default gen_random_uuid(), email text, raw_user_meta_data jsonb default '{}', raw_app_meta_data jsonb default '{}', created_at timestamptz default now());
create or replace function auth.uid() returns uuid language sql stable as $f$ select nullif(nullif(current_setting('request.jwt.claims',true),'')::jsonb->>'sub','')::uuid $f$;
create or replace function auth.jwt() returns jsonb language sql stable as $f$ select coalesce(nullif(current_setting('request.jwt.claims',true),'')::jsonb,'{}') $f$;
create or replace function auth.role() returns text language sql stable as $f$ select coalesce(nullif(current_setting('request.jwt.claims',true),'')::jsonb->>'role','anon') $f$;
do $d$ begin
  if not exists(select from pg_roles where rolname='anon') then create role anon; end if;
  if not exists(select from pg_roles where rolname='authenticated') then create role authenticated; end if;
  if not exists(select from pg_roles where rolname='supabase_auth_admin') then create role supabase_auth_admin; end if;
  if not exists(select from pg_roles where rolname='service_role') then create role service_role; end if;
  if not exists(select from pg_roles where rolname='supabase_realtime_admin') then create role supabase_realtime_admin; end if;
end $d$;
create schema if not exists storage;
create table if not exists storage.buckets (id text primary key, name text, public boolean default false, file_size_limit bigint, allowed_mime_types text[], created_at timestamptz default now());
create table if not exists storage.objects (id uuid primary key default gen_random_uuid(), bucket_id text, name text, owner uuid, created_at timestamptz default now());
create schema if not exists realtime;
create table if not exists realtime.messages (id bigserial primary key, topic text, extension text, payload jsonb, event text, private boolean default true, inserted_at timestamptz default now());
create or replace function realtime.topic() returns text language sql stable as $f$ select current_setting('realtime.topic', true) $f$;
create or replace function realtime.send(payload jsonb, event text, topic text, private boolean default true) returns void language sql as $f$ insert into realtime.messages(topic, payload, event, private) values (topic, payload, event, private) $f$;
create or replace function realtime.broadcast_changes(topic_name text, event_name text, operation text, table_name text, table_schema text, new record, old record, level text default 'ROW') returns void language plpgsql as $f$ begin end $f$;
create schema if not exists cron;
create table if not exists cron.job (jobid bigserial primary key, jobname text unique, schedule text, command text, active boolean default true);
create table if not exists cron.job_run_details (runid bigserial primary key, jobid bigint, status text, start_time timestamptz, end_time timestamptz);
create or replace function cron.schedule(job_name text, schedule text, command text) returns bigint language plpgsql as $f$ declare v bigint; begin insert into cron.job(jobname, schedule, command) values (job_name, schedule, command) on conflict (jobname) do update set schedule = excluded.schedule, command = excluded.command returning jobid into v; return v; end $f$;
create or replace function cron.unschedule(job_name text) returns boolean language plpgsql as $f$ begin delete from cron.job where jobname = job_name; return true; end $f$;
create or replace function cron.alter_job(job_id bigint, schedule text default null, command text default null, database text default null, username text default null, active boolean default null) returns void language plpgsql as $f$ begin update cron.job set active = coalesce(alter_job.active, cron.job.active) where jobid = job_id; end $f$;
grant usage on schema public, auth, storage, realtime, cron to anon, authenticated, service_role, supabase_auth_admin;
alter default privileges in schema public grant select, insert, update, delete on tables to authenticated, anon;
alter default privileges in schema public grant execute on functions to anon, authenticated;
create or replace function public.uuid_generate_v4() returns uuid language sql as $f$ select gen_random_uuid() $f$;`;

/** Fresh DB with every migration applied. Returns { db, q, one, failed } — `failed` lists migrations that errored. */
export async function freshDb({ stopOnError = true } = {}) {
  const db = new PGlite();
  await db.exec(SHIM);
  const failed = [];
  for (const f of readdirSync(MIG).filter(f => f.endsWith(".sql")).sort()) {
    try {
      await db.exec(readFileSync(join(MIG, f), "utf8").replace(/create extension[^;]*;/gi, ""));
    } catch (e) {
      failed.push(`${f}: ${String(e.message).split("\n")[0]}`);
      if (stopOnError) throw new Error(`migration ${f} failed: ${e.message}`);
    }
  }
  // Supabase's service_role has full table access (it bypasses RLS); mirror that.
  await db.exec(`grant all on all tables in schema public to service_role; grant all on all sequences in schema public to service_role; alter role service_role bypassrls;`);
  const q = (sql, p = []) => db.query(sql, p);
  const one = async (sql, p = []) => (await q(sql, p)).rows[0];
  return { db, q, one, failed };
}

/** Run `fn` as a signed-in client (role authenticated, auth.uid() = uid, plus any extra JWT claims such as org_id), inside a transaction that is rolled back. */
export async function asUser(db, uid, fn, extraClaims = {}) {
  await db.exec("begin");
  try {
    await db.exec(`set local role authenticated; select set_config('request.jwt.claims', '${JSON.stringify({ sub: uid, role: "authenticated", ...extraClaims })}', true);`);
    return await fn();
  } finally {
    await db.exec("rollback");
  }
}
