// 0109 content_time: active time on lessons and quizzes, written only through add_content_time
// (service role), read by the learner (own rows) and deleted with the organization.
// Runs every migration in PGlite (no Docker / Supabase needed).
//
// Run: node scripts/test-0109-db.mjs
import { randomUUID } from "node:crypto";
import { freshDb } from "./lib/pgliteHarness.mjs";

let pass = 0, fail = 0; const failures = [];
function check(name, cond, extra = "") {
  if (cond) pass++; else { fail++; failures.push(name + (extra ? ` (${extra})` : "")); }
  console.log(`  ${cond ? "PASS" : "FAIL"} ${name}${extra ? `  (${extra})` : ""}`);
}
const group = t => console.log(`\n${t}`);

const { db, q, one } = await freshDb();
const org = randomUUID();
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-0109',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODE0109', now() + interval '1 day')`, [org]);
const signup = async email => { const id = randomUUID(); await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [id, email, JSON.stringify({ org_code: "CODE0109" })]); return id; };
const [a, b] = [await signup("a@x.test"), await signup("b@x.test")];

async function as(role, uid, fn) {
  await db.exec("begin");
  try {
    await db.exec(`set local role ${role}; select set_config('request.jwt.claims', '${JSON.stringify({ sub: uid, role })}', true);`);
    const r = await fn(); await db.exec("commit"); return { r, err: null };
  } catch (e) { await db.exec("rollback"); return { r: null, err: String(e.message) }; }
}
const add = (uid, kind, item, sec) => as("service_role", uid, () => db.query(`select public.add_content_time($1,$2,$3,$4,$5) as total`, [uid, org, kind, item, sec]));

group("1. beats add up, each capped at 120 seconds");
let r = await add(a, "lesson", "soc-analyst--what-is-a-soc", 60);
check("first beat", !r.err && Number(r.r.rows[0].total) === 60, r.err ?? "");
r = await add(a, "lesson", "soc-analyst--what-is-a-soc", 999);
check("an oversized beat counts 120", !r.err && Number(r.r.rows[0].total) === 180, r.err ?? String(r.r?.rows[0]?.total));
r = await add(a, "lesson", "soc-analyst--what-is-a-soc", -50);
check("a negative beat adds nothing", !r.err && Number(r.r.rows[0].total) === 180);
r = await add(a, "quiz", "mitre-attack", 45);
check("quizzes are counted apart from lessons", !r.err && Number(r.r.rows[0].total) === 45);
r = await add(a, "room", "x", 10);
check("only lesson and quiz kinds", !!r.err);

group("2. learners read only their own rows and cannot write");
await add(b, "lesson", "soc-analyst--what-is-a-soc", 30);
r = await as("authenticated", a, () => db.query(`select user_id, seconds from public.content_time`));
check("a sees only a's rows", !r.err && r.r.rows.length === 2 && r.r.rows.every(x => x.user_id === a), r.err ?? JSON.stringify(r.r?.rows));
r = await as("authenticated", a, () => db.query(`select public.add_content_time($1,$2,'lesson','soc-analyst--what-is-a-soc',120)`, [a, org]));
check("a learner cannot call add_content_time", !!r.err);
r = await as("authenticated", a, () => db.query(`insert into public.content_time (user_id, kind, item_id, seconds) values ($1,'lesson','x',9999)`, [a]));
check("a learner cannot insert", !!r.err);
r = await as("authenticated", a, () => db.query(`update public.content_time set seconds = 99999 where user_id = $1`, [a]));
const after = await one(`select seconds from public.content_time where user_id = $1 and kind = 'lesson'`, [a]);
check("a learner cannot change their total", !!r.err || Number(after.seconds) === 180);
r = await as("anon", a, () => db.query(`select count(*) from public.content_time`));
check("anon reads nothing", !!r.err || Number(r.r.rows[0].count) === 0);

group("3. deleting the organization deletes its rows (purge_org deletes the org row)");
// Called as the owner, as the super-admin route does (test-phase4-db.mjs does the same).
let purgeErr = null;
try { await q(`select public.purge_org($1)`, [org]); } catch (e) { purgeErr = String(e.message); }
check("purge_org runs", !purgeErr, purgeErr ?? "");
const left = await one(`select count(*)::int as n from public.content_time where org_id = $1`, [org]);
check("no rows left for the deleted org", Number(left.n) === 0);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.join("\n")); process.exit(1); }
