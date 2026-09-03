#!/usr/bin/env node
/**
 * RLS coverage gate (HTS-SEC-001).
 *
 * The client talks to Supabase PostgREST directly with the user's anon JWT, so Row
 * Level Security IS the entire authorization layer — one table with RLS off, or a
 * user-data table missing a self-scoping policy, means one student can read another's
 * data by changing a filter. This gate makes that a hard, checkable invariant instead
 * of a MUST-VERIFY note:
 *
 *   1. EVERY public base table must have RLS enabled.
 *   2. EVERY user-data table must carry a policy that scopes rows to the current user
 *      (auth.uid()).
 *   3. Tables with RLS on and ZERO policies are reported as deny-all (locked) — correct
 *      for the zero-grant answer keys and service-role-only tables, never a failure.
 *
 * Needs DATABASE_URL (read-only; queries pg_catalog only). Run:  npm run validate:rls
 * Exit 0 = clean, 1 = a real RLS gap, 2 = could not connect (skipped, not failed).
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// Rows in these tables belong to one user and must be scoped to auth.uid().
const USER_DATA_TABLES = new Set([
  "profiles", "user_progress", "room_progress", "dashboard_sessions",
  "scenario_history", "task_attempts", "ai_usage", "account_deletion_requests",
]);

function readDbUrl() {
  if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
  for (const f of [".env.local", ".env"]) {
    const p = path.join(ROOT, f);
    if (fs.existsSync(p)) {
      const m = fs.readFileSync(p, "utf-8").match(/^\s*DATABASE_URL\s*=\s*"?([^"\n]+)"?/m);
      if (m) return m[1];
    }
  }
  return null;
}

const url = readDbUrl();
if (!url) {
  console.log("validate:rls  SKIP — no DATABASE_URL (set it to run the RLS gate).");
  process.exit(2);
}

const client = new pg.Client({ connectionString: url, ssl: { rejectUnauthorized: false } });
try {
  await client.connect();
} catch (e) {
  console.log(`validate:rls  SKIP — could not connect (${e.code || e.message}).`);
  process.exit(2);
}

const tables = (await client.query(`
  select t.relname as table, t.relrowsecurity as rls,
    (select count(*) from pg_policies p where p.schemaname='public' and p.tablename=t.relname)::int as policies
  from pg_class t join pg_namespace n on n.oid=t.relnamespace
  where n.nspname='public' and t.relkind='r' order by t.relname;
`)).rows;

const selfScoped = new Map();  // table -> has a policy referencing auth.uid()
for (const p of (await client.query(`
  select tablename, qual, with_check from pg_policies where schemaname='public';
`)).rows) {
  const refsUser = /auth\.uid\(\)/.test(`${p.qual ?? ""} ${p.with_check ?? ""}`);
  if (refsUser) selfScoped.set(p.tablename, true);
}
await client.end();

const failures = [];
let denyAll = 0;
for (const t of tables) {
  if (!t.rls) failures.push(`${t.table}: RLS is OFF — client can read/write every row`);
  else if (t.policies === 0) denyAll++;
  if (USER_DATA_TABLES.has(t.table) && !selfScoped.get(t.table))
    failures.push(`${t.table}: user-data table has no auth.uid()-scoped policy`);
}

console.log(`RLS gate — ${tables.length} public tables, ${denyAll} deny-all (locked), ${failures.length} gap(s)`);
if (failures.length) {
  for (const f of failures) console.log(`  \x1b[31m✗ ${f}\x1b[0m`);
  console.log("\n  FAIL — an RLS gap means cross-user data exposure.");
  process.exit(1);
}
console.log("  \x1b[32mPASS — every table has RLS on; every user-data table is scoped to auth.uid().\x1b[0m");
