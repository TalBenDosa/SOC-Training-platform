// QA PHASE 7 (error handling) — DB-level checks for migrations 0085 + 0086.
// Runs every migration in PGlite (no Docker / Supabase needed).
//
// Run: node scripts/test-phase7-db.mjs
import { randomUUID } from "node:crypto";
import { freshDb } from "./lib/pgliteHarness.mjs";

let pass = 0, fail = 0; const failures = [];
function check(name, cond, extra = "") {
  if (cond) pass++; else { fail++; failures.push(name + (extra ? ` — ${extra}` : "")); }
  console.log(`  ${cond ? "✅" : "❌"} ${name}${extra ? `  (${extra})` : ""}`);
}
const group = t => console.log(`\n\x1b[1m${t}\x1b[0m`);

const { q, one } = await freshDb();
const org = randomUUID();
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-p7',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODEP7AA', now() + interval '1 day')`, [org]);
const signup = async email => { const id = randomUUID(); await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [id, email, JSON.stringify({ org_code: "CODEP7AA" })]); return id; };
const owner = await signup("owner@p7.test");

group("E-20 reaper ends abandoned lobbies");
const oldLobby = randomUUID(), newLobby = randomUUID(), running = randomUUID();
await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status, created_at) values ($1,$2,$3,'nexacorp','lobby', now() - interval '25 hours')`, [oldLobby, org, owner]);
await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status, created_at) values ($1,$2,$3,'nexacorp','lobby', now() - interval '2 hours')`, [newLobby, org, owner]);
await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status, schema_version, started_at) values ($1,$2,$3,'nexacorp','running',2, now() - interval '5 minutes')`, [running, org, owner]);
const reaped = (await one(`select public.reap_stale_team_sessions() n`)).n;
const st = async id => (await one(`select status from public.team_sessions where id=$1`, [id])).status;
check("a 25 h old lobby is ended", (await st(oldLobby)) === "ended", `reaped=${reaped}`);
check("a 2 h old lobby is left alone", (await st(newLobby)) === "lobby");
check("a fresh running session is left alone", (await st(running)) === "running");
check("no reap errors recorded", (await one(`select count(*)::int c from public.team_ops_events where kind='reap_error'`)).c === 0);
check("students can't call the reaper", (await one(`select has_function_privilege('authenticated','public.reap_stale_team_sessions()','execute') v`)).v === false);

group("E-06 team_ops_events dedupe + purge");
for (let i = 0; i < 5; i++) await q(`insert into public.team_ops_events(kind, session_id, detail) values ('broadcast_failed', $1, 'realtime down')`, [running]);
check("5 identical errors within a minute → 1 row", (await one(`select count(*)::int c from public.team_ops_events where kind='broadcast_failed'`)).c === 1);
await q(`insert into public.team_ops_events(kind, session_id, detail) values ('broadcast_failed', $1, 'different detail')`, [running]);
await q(`insert into public.team_ops_events(kind, session_id, detail) values ('promote_error', $1, 'realtime down')`, [running]);
check("a different detail / kind is still recorded", (await one(`select count(*)::int c from public.team_ops_events`)).c === 3);
await q(`insert into public.team_ops_events(kind, session_id, detail, at) values ('broadcast_failed', $1, 'realtime down', now() - interval '2 minutes')`, [newLobby]);
check("the same error for another session is recorded", (await one(`select count(*)::int c from public.team_ops_events`)).c === 4);
const purge = await one(`select command from cron.job where jobname='team-ops-purge'`).catch(() => null);
check("daily purge job scheduled (14 days)", !!purge && /14 days/.test(purge.command));
check("team_ops_health still readable by service role", (await one(`select ops_errors_1h::int n from public.team_ops_health`)).n >= 3);

group("Info: auth hook never blocks a sign-in");
const ev = (uid) => JSON.stringify({ user_id: uid, claims: { sub: uid, role: "authenticated", aud: "authenticated" } });
const good = (await one(`select public.custom_access_token_hook($1::jsonb) r`, [ev(owner)])).r;
check("normal path unchanged — org claims present", good.claims.org_id === org && good.claims.is_platform_admin === false, JSON.stringify(good.claims).slice(0, 120));
const bad = (await one(`select public.custom_access_token_hook($1::jsonb) r`, [JSON.stringify({ user_id: "not-a-uuid", claims: { sub: "x", role: "authenticated", org_id: "spoof", is_platform_admin: true } })])).r;
check("an internal error returns claims instead of raising", !!bad?.claims);
check("…with privileges dropped (fail closed)", bad.claims.org_id === undefined && bad.claims.is_platform_admin === false);
check("auth admin can still execute the hook", (await one(`select has_function_privilege('supabase_auth_admin','public.custom_access_token_hook(jsonb)','execute') v`)).v === true);
check("clients cannot execute the hook", (await one(`select has_function_privilege('authenticated','public.custom_access_token_hook(jsonb)','execute') v`)).v === false);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.map(f => "  - " + f).join("\n")); process.exit(1); }
