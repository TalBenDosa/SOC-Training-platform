// Migration 0117 (film_playback_events) on PGlite: applies cleanly and idempotently, RLS is on with
// no policies, learners can neither read nor write it, and the service role can insert.
// Usage: node scripts/test-0117-db.mjs
import { readFileSync } from "node:fs";
import { freshDb, asUser } from "./lib/pgliteHarness.mjs";

const { db, q, one } = await freshDb();
let failures = 0;
const check = (ok, label) => { console.log(`${ok ? "PASS" : "FAIL"}  ${label}`); if (!ok) failures++; };
const denied = async (fn) => { try { await fn(); return false; } catch { return true; } };

const uid = "11111111-1111-4111-8111-111111111111";
// The signup trigger (class codes) is not under test here: insert the user with triggers off.
await db.exec("set session_replication_role = replica");
await q(`insert into auth.users (id, email) values ($1, 'learner@example.test') on conflict do nothing`, [uid]);
await db.exec("set session_replication_role = origin");

check((await one(`select relrowsecurity from pg_class where relname = 'film_playback_events'`)).relrowsecurity === true, "RLS is enabled");
check(Number((await one(`select count(*)::int as n from pg_policies where tablename = 'film_playback_events'`)).n) === 0, "no policies (server-only table)");

await db.exec("set role service_role");
await q(`insert into public.film_playback_events (user_id, src_path, kind, wait_ms) values ($1, 'operation/x/y.mp4', 'recovered', 4200)`, [uid]);
await db.exec("reset role");
check(Number((await one(`select count(*)::int as n from public.film_playback_events`)).n) === 1, "the service role inserts a row");

check(await denied(() => q(`insert into public.film_playback_events (user_id, src_path, kind) values ('${uid}', 'a.mp4', 'bogus')`)), "an unknown kind is rejected by the check");

check(await asUser(db, uid, () => denied(() => q(`select * from public.film_playback_events`))), "a learner cannot read the table");
check(await asUser(db, uid, () => denied(() => q(`insert into public.film_playback_events (user_id, src_path, kind) values ('${uid}', 'a.mp4', 'start')`))), "a learner cannot insert");

await db.exec(readFileSync(new URL("../supabase/migrations/0117_film_playback_events.sql", import.meta.url), "utf8"));
check(Number((await one(`select count(*)::int as n from public.film_playback_events`)).n) === 1, "re-applying the migration keeps the data (idempotent)");

console.log(failures ? `\n${failures} FAILED` : "\nALL PASSED");
process.exit(failures ? 1 : 0);
