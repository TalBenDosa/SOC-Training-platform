// 0087 — team training XP. Runs every migration in PGlite.
// Run: node scripts/test-team-xp-db.mjs
import { randomUUID } from "node:crypto";
import { freshDb, asUser } from "./lib/pgliteHarness.mjs";

let pass = 0, fail = 0; const failures = [];
function check(name, cond, extra = "") {
  if (cond) pass++; else { fail++; failures.push(name + (extra ? ` — ${extra}` : "")); }
  console.log(`  ${cond ? "✅" : "❌"} ${name}${extra ? `  (${extra})` : ""}`);
}
const { db, q, one } = await freshDb();
const org = randomUUID();
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-txp',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODETXPA', now() + interval '1 day')`, [org]);
const signup = async email => { const id = randomUUID(); await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [id, email, JSON.stringify({ org_code: "CODETXPA" })]); return id; };
const a = await signup("a@txp.test"), b = await signup("b@txp.test"), outsider = await signup("c@txp.test");
const xpOf = async u => (await one(`select xp from public.profiles where id=$1`, [u])).xp;
const baseA = await xpOf(a);

const ended = randomUUID(), live = randomUUID();
await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status, started_at, ended_at) values ($1,$2,$3,'nexacorp','ended', now() - interval '1 hour', now())`, [ended, org, a]);
await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status, schema_version, started_at) values ($1,$2,$3,'nexacorp','running',2, now())`, [live, org, a]);
for (const [s, u, r] of [[ended, a, "t1"], [ended, b, "t2"], [live, a, "t1"]]) await q(`insert into public.team_session_members (session_id, user_id, role, status) values ($1,$2,$3,'ready')`, [s, u, r]);

console.log("\n0087 team training XP");
const rows = JSON.stringify([{ user_id: a, xp: 120 }, { user_id: b, xp: 90 }, { user_id: outsider, xp: 200 }]);
const n = (await one(`select public.award_team_session_xp($1, $2::jsonb, 1) n`, [ended, rows])).n;
check("awards only the session's roster", n === 2, String(n));
check("player A's total includes the session XP", (await xpOf(a)) === baseA + 120, `${await xpOf(a)}`);
check("an outsider gets nothing", (await xpOf(outsider)) === 0);
await one(`select public.award_team_session_xp($1, $2::jsonb, 1) n`, [ended, rows]);
check("awarding again doesn't double-credit", (await xpOf(a)) === baseA + 120);
await one(`select public.award_team_session_xp($1, $2::jsonb, 1) n`, [ended, JSON.stringify([{ user_id: a, xp: 150 }])]);
check("a re-award replaces the value", (await xpOf(a)) === baseA + 150);
await one(`select public.award_team_session_xp($1, $2::jsonb, 1) n`, [ended, JSON.stringify([{ user_id: b, xp: 99999 }])]);
check("XP is clamped to 200 per session", (await one(`select xp from public.team_session_xp where session_id=$1 and user_id=$2`, [ended, b])).xp === 200);
let refused = false;
try { await q(`select public.award_team_session_xp($1, $2::jsonb, 1)`, [live, JSON.stringify([{ user_id: a, xp: 50 }])]); } catch { refused = true; }
check("a running session can't be awarded", refused);
check("other XP sources still count (recompute keeps rooms)", await (async () => {
  await q(`insert into public.room_progress (user_id, room_id, org_id, completed_task_ids, per_task_xp, xp_earned) values ($1,'r1',$2,'[]','{}',30)`, [a, org]);
  await q(`select public.recompute_user_xp($1)`, [a]);
  return (await xpOf(a)) === baseA + 150 + 30;
})());
const canSee = await asUser(db, a, () => db.query(`select count(*)::int c from public.team_session_xp`), { org_id: org });
check("a player reads only their own XP rows", canSee.rows[0].c === 1, String(canSee.rows[0].c));
let blocked = false;
try { await asUser(db, a, () => db.query(`select public.award_team_session_xp('${ended}', '[]'::jsonb, 1)`), { org_id: org }); } catch { blocked = true; }
check("players can't call the award function", blocked);
let noWrite = false;
try { await asUser(db, a, () => db.query(`insert into public.team_session_xp (session_id,user_id,xp) values ('${live}','${a}',200)`), { org_id: org }); } catch { noWrite = true; }
check("players can't write XP rows", noWrite);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.map(f => "  - " + f).join("\n")); process.exit(1); }
