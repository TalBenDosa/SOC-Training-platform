// QA PHASE 6 (security) — DB-level checks for migration 0083.
// Runs every migration in PGlite (no Docker / Supabase needed).
//
// Run: node scripts/test-phase6-db.mjs
import { randomUUID } from "node:crypto";
import { freshDb, asUser } from "./lib/pgliteHarness.mjs";

let pass = 0, fail = 0; const failures = [];
function check(name, cond, extra = "") {
  if (cond) pass++; else { fail++; failures.push(name + (extra ? ` — ${extra}` : "")); }
  console.log(`  ${cond ? "✅" : "❌"} ${name}${extra ? `  (${extra})` : ""}`);
}
const group = t => console.log(`\n\x1b[1m${t}\x1b[0m`);
async function denied(db, uid, sql, claims) {
  try { await asUser(db, uid, () => db.query(sql), claims); return false; }
  catch (e) { return /permission denied|violates row-level security/i.test(String(e.message)); }
}

const { db, q, one } = await freshDb();
const org = randomUUID();
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-p6',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODEP6AA', now() + interval '1 day')`, [org]);
const signup = async email => { const id = randomUUID(); await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [id, email, JSON.stringify({ org_code: "CODEP6AA" })]); return id; };
const stu = await signup("stu@p6.test");
const other = await signup("other@p6.test");

group("SEC-05 revoke_user_sessions");
for (const u of [stu, stu, other]) {
  const s = (await one(`insert into auth.sessions (user_id) values ($1) returning id`, [u])).id;
  await q(`insert into auth.refresh_tokens (session_id, user_id, token) values ($1,$2,'t')`, [s, u]);
}
const n = (await one(`select public.revoke_user_sessions($1) n`, [stu])).n;
check("removes every session of the user (2)", n === 2, String(n));
check("…and their refresh tokens (cascade)", (await one(`select count(*)::int c from auth.refresh_tokens where user_id=$1`, [stu])).c === 0);
check("other users' sessions untouched", (await one(`select count(*)::int c from auth.sessions where user_id=$1`, [other])).c === 1);
check("students cannot call revoke_user_sessions", await denied(db, stu, `select public.revoke_user_sessions('${other}')`, { org_id: org }));


// asUser() rolls back; these need the row to land.
async function asUserCommit(uid, fn, claims = {}) {
  await db.exec("begin");
  try {
    await db.exec(`set local role authenticated; select set_config('request.jwt.claims', '${JSON.stringify({ sub: uid, role: "authenticated", ...claims })}', true);`);
    const r = await fn(); await db.exec("commit"); return r;
  } catch (e) { await db.exec("rollback"); throw e; }
}
const claims = { org_id: org, org_role: "student" };
const insSession = (vals) => asUserCommit(stu, () => db.query(
  `insert into public.dashboard_sessions (user_id, org_id, played_at, xp_earned, detect_rate, fn_count, attacks_caught_count, attacks_presented_count, events_opened_count, duration_ms)
   values ($1,$2,$3,$4,$5,0,$6,$7,$8,$9) returning played_at, detect_rate, attacks_caught_count`,
  [stu, org, vals.played_at ?? new Date().toISOString(), vals.xp ?? 50, vals.rate ?? 0, vals.caught ?? 0, vals.presented ?? 0, vals.opened ?? 10, vals.dur ?? 600000]), claims);
const err = async (p) => { try { await p; return null; } catch (e) { return String(e.message); } };

group("SEC-07 dashboard_sessions");
const ok = await insSession({ caught: 3, presented: 4, rate: 75 });
check("a real shift is accepted", ok.rows[0].detect_rate === 75);
const forged = await insSession({ caught: 0, presented: 8, rate: 100 });
check("a forged 100% on 0-of-8 is stored as 0% (derived from the counts)", forged.rows[0].detect_rate === 0, String(forged.rows[0].detect_rate));
const over = await insSession({ caught: 9, presented: 4, rate: 100 });
check("caught can't exceed presented (capped)", over.rows[0].attacks_caught_count === 4 && over.rows[0].detect_rate === 100);
const back = await insSession({ played_at: "2020-01-01T00:00:00Z", caught: 1, presented: 1 });
check("played_at can't be backdated", new Date(back.rows[0].played_at).getFullYear() > 2020);
check("negative values refused", /negative value/.test((await err(insSession({ caught: -1, presented: 2 }))) ?? ""));
check("absurd values refused", /out of range/.test((await err(insSession({ xp: 999999 }))) ?? ""));
check("a student can't UPDATE a past session", await denied(db, stu, `update public.dashboard_sessions set detect_rate = 100 where user_id = '${stu}'`, claims));
check("…nor DELETE one", await denied(db, stu, `delete from public.dashboard_sessions where user_id = '${stu}'`, claims));
for (let i = 0; i < 26; i++) await insSession({ caught: 1, presented: 2 });
check("more than 30 sessions an hour refused", /too many sessions/.test((await err(insSession({ caught: 1, presented: 2 }))) ?? ""));

group("SEC-08 ai_usage");
check("a student can't delete their metering rows", await denied(db, stu, `delete from public.ai_usage where user_id = '${stu}'`, claims));
check("…nor insert fake spend", await denied(db, stu, `insert into public.ai_usage (user_id, org_id) values ('${stu}', '${org}')`, claims));
check("…but may read their own", !(await denied(db, stu, `select * from public.ai_usage where user_id = '${stu}'`, claims)));

group("SEC-20 grants");
const trunc = (await one(`select count(*)::int n from information_schema.role_table_grants where table_schema='public' and grantee in ('anon','authenticated') and privilege_type='TRUNCATE'`)).n;
check("no TRUNCATE for anon / authenticated on any table", trunc === 0, String(trunc));
const anonW = (await one(`select count(*)::int n from information_schema.role_table_grants where table_schema='public' and grantee='anon' and privilege_type in ('INSERT','UPDATE','DELETE')`)).n;
check("anon holds no write grant", anonW === 0, String(anonW));

group("SEC-21 profiles.rank / streak_days");
await asUserCommit(stu, () => db.query(`update public.profiles set rank = 'Elite', streak_days = 999, bio = 'hi' where id = $1`, [stu]), claims);
const pr = await one(`select rank, streak_days, bio from public.profiles where id = $1`, [stu]);
check("a learner can't set their own rank / streak", pr.rank !== "Elite" && pr.streak_days !== 999, JSON.stringify(pr));
check("…while their bio still saves", pr.bio === "hi");

console.log(`\n${fail ? "\x1b[31mFAIL" : "\x1b[32mPASS"}\x1b[0m — ${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.map(f => `  - ${f}`).join("\n")); process.exit(1); }
