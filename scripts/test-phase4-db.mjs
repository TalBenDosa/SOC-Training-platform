// QA PHASE 4 (database) — DB-level checks for migration 0080 and the export's
// sort columns. Runs every migration in PGlite (no Docker / Supabase needed).
//
// Run: node scripts/test-phase4-db.mjs
import { randomUUID } from "node:crypto";
import fs from "node:fs";
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
async function raises(q, sql, params, pattern) {
  try { await q(sql, params); return false; } catch (e) { return pattern.test(String(e.message)); }
}

const { db, q, one } = await freshDb();
const mkOrg = async (name, seats = 100) => {
  const id = randomUUID();
  await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,$2,$3,$4,'active',now())`, [id, name, name.toLowerCase().replace(/\W+/g, "-") + id.slice(0, 4), seats]);
  return id;
};
const mkCode = async (org, code) => q(`insert into public.org_codes (org_id, code, expires_at) values ($1,$2, now() + interval '1 day')`, [org, code]);
const signup = async (email, meta) => { const id = randomUUID(); await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [id, email, JSON.stringify(meta)]); return id; };

const orgA = await mkOrg("College A");
const orgB = await mkOrg("College B");
await mkCode(orgA, "CODEAAAA"); await mkCode(orgB, "CODEBBBB");
const stu = await signup("stu@p4.test", { org_code: "CODEAAAA" });

group("P4-03 atomic attempt numbers");
const claim = async (qidx = null) => (await one(`select public.claim_task_attempt($1,'room-x','task-1',$2) as n`, [stu, qidx])).n;
check("first claim on a fresh task = 1", (await claim()) === 1);
check("second claim = 2 (the ON CONFLICT increment)", (await claim()) === 2);
check("log_analysis sub-questions count separately", (await claim(0)) === 1 && (await claim(1)) === 1 && (await claim(0)) === 2);
await q(`insert into public.task_attempts (user_id, room_id, task_id, task_type, correct, attempt_no) values ($1,'room-y','t',  'question', false, 1),($1,'room-y','t','question',false,2)`, [stu]);
check("seeded from attempts already recorded (2 existing → 3)", (await one(`select public.claim_task_attempt($1,'room-y','t') as n`, [stu])).n === 3);
check("students cannot call claim_task_attempt", await denied(db, stu, `select public.claim_task_attempt('${stu}','r','t')`));
check("students cannot read the counters", await denied(db, stu, `select * from public.task_attempt_counters`));

group("P4-05 org_resources.storage_key");
await q(`insert into public.org_resources (org_id, kind, title, storage_key, mime, size_bytes) values ($1,'pdf','Doc',$2,'application/pdf',10)`, [orgA, `${orgA}/pdf/one.pdf`]).catch(e => console.log("   (insert note)", e.message));
const okRow = await one(`select count(*)::int n from public.org_resources where org_id=$1`, [orgA]);
check("a key under the org's prefix is accepted", okRow.n === 1);
check("the same storage_key twice is rejected (unique)", await raises(q, `insert into public.org_resources (org_id, kind, title, storage_key, mime, size_bytes) values ($1,'pdf','Dup',$2,'application/pdf',10)`, [orgA, `${orgA}/pdf/one.pdf`], /unique|duplicate/i));
check("a key outside the org's prefix is rejected", await raises(q, `insert into public.org_resources (org_id, kind, title, storage_key, mime, size_bytes) values ($1,'pdf','X',$2,'application/pdf',10)`, [orgA, `${orgB}/pdf/theirs.pdf`], /check|prefix/i));
check("clients cannot UPDATE org_resources (no retargeting a key)", await denied(db, stu, `update public.org_resources set storage_key = '${orgA}/pdf/x.pdf'`, { org_id: orgA, org_role: "org_admin" }));

group("P4-09 seats exclude the platform admin");
const small = await mkOrg("Small College", 1);
await mkCode(small, "CODESMAL");
const admin = await signup("tal@p4.test", { org_code: "CODEAAAA" });
await q(`update public.profiles set is_platform_admin = true where id=$1`, [admin]);
await q(`insert into public.org_members (org_id, user_id, role, status) values ($1,$2,'org_admin','active')`, [small, admin]);
check("org_seats_used ignores the platform admin", (await one(`select public.org_seats_used($1) as n`, [small])).n === 0);
const s1 = await signup("first@p4.test", { org_code: "CODESMAL" }).catch(() => null);
check("a 1-seat college still admits its first student when the admin is inside", !!s1 && !!(await one(`select 1 as x from public.org_members where user_id=$1 and org_id=$2`, [s1, small])));
check("…and the seat limit still holds for the next one", await raises(q, `insert into auth.users (id,email,raw_user_meta_data) values ($1,'second@p4.test','{"org_code":"CODESMAL"}')`, [randomUUID()], /seat_limit_reached/));

group("P4-10 invitations are single-use");
await q(`insert into public.invitations (org_id, email, role, token, expires_at) values ($1, null, 'instructor', 'tok-generic', now() + interval '1 day')`, [orgA]);
const inv1 = await signup("staff1@p4.test", { invitation_token: "tok-generic" }).catch(() => null);
check("first signup on a generic staff link succeeds", !!inv1);
check("second signup on the same link fails", await raises(q, `insert into auth.users (id,email,raw_user_meta_data) values ($1,'staff2@p4.test','{"invitation_token":"tok-generic"}')`, [randomUUID()], /invitation_invalid/));

group("P4-08 reactivate_member");
const full = await mkOrg("Full College", 1);
const m1 = await signup("m1@p4.test", { org_code: "CODEAAAA" });
const m2 = await signup("m2@p4.test", { org_code: "CODEAAAA" });
await q(`insert into public.org_members (org_id, user_id, role, status) values ($1,$2,'student','active'),($1,$3,'student','removed')`, [full, m1, m2]);
check("reactivation past the seat limit is refused", await raises(q, `select public.reactivate_member($1,$2)`, [full, m2], /seat_limit_reached/));
await q(`update public.org_members set status='removed' where org_id=$1 and user_id=$2`, [full, m1]);
check("reactivation within the limit works", (await one(`select public.reactivate_member($1,$2) as r`, [full, m2])).r === "reactivated");
check("reactivating a stranger reports not_member", (await one(`select public.reactivate_member($1,$2) as r`, [full, randomUUID()])).r === "not_member");
check("students cannot call reactivate_member", await denied(db, stu, `select public.reactivate_member('${full}','${m1}')`));

group("P4-14 attach sets the affiliation expiry atomically");
const joiner = await signup("joiner@p4.test", { org_code: "CODEAAAA" });
await q(`select public.attach_member_if_seat_available($1,$2,'student', now() + interval '100 days')`, [orgB, joiner]);
const aff = await one(`select affiliation_expires_at from public.org_members where org_id=$1 and user_id=$2`, [orgB, joiner]);
check("expiry written with the membership", !!aff?.affiliation_expires_at);
check("3-argument calls still work (named args, default)", (await one(`select public.attach_member_if_seat_available(p_org => $1, p_user => $2, p_role => 'student') as r`, [orgB, stu])).r === "added");

group("P4-11 renew_affiliation uses the code's college");
// stu is now a student in A (signup) and B (attach above).
await q(`select public.renew_affiliation($1,'CODEBBBB')`, [stu]);
const renewed = await one(`select affiliation_expires_at from public.org_members where org_id=$1 and user_id=$2`, [orgB, stu]);
check("renewing with B's code renews the B membership (no wrong-org error)", !!renewed?.affiliation_expires_at);
const loner = await signup("loner@p4.test", { org_code: "CODEAAAA" });
check("a code from a college the student isn't in → org_code_wrong_org", await raises(q, `select public.renew_affiliation($1,'CODEBBBB')`, [loner], /org_code_wrong_org/));

group("P4-15 issue_org_code");
const codeOrg = await mkOrg("Code College");
const issue = (code, cooldown) => one(`select * from public.issue_org_code($1,null,$2, now() + interval '24 hours', $3)`, [codeOrg, code, cooldown]);
await issue("FIRSTONE", 24);
check("a second generation inside the cooldown is refused", await raises(q, `select * from public.issue_org_code($1,null,'SECONDXX', now() + interval '24 hours', 24)`, [codeOrg], /code_cooldown/));
await issue("SUPERADM", 0);
check("exactly one live code after a (super-admin) regeneration", (await one(`select count(*)::int n from public.org_codes where org_id=$1 and expires_at > now()`, [codeOrg])).n === 1);
check("…and it's the new one", (await one(`select code from public.org_codes where org_id=$1 and expires_at > now()`, [codeOrg])).code === "SUPERADM");

group("P4-13 purge_org removes all learner data of the college");
const gone = await mkOrg("Leaving College");
await mkCode(gone, "CODEGONE");
const gs = await signup("gs@p4.test", { org_code: "CODEGONE" });
await q(`insert into public.quiz_progress (user_id, quiz_slug, org_id, xp_earned) values ($1,'q1',$2,10)`, [gs, gone]);
await q(`insert into public.lesson_progress (user_id, lesson_key, org_id) values ($1,'p--l1',$2)`, [gs, gone]);
await q(`insert into public.task_attempts (user_id, org_id, room_id, task_id, task_type, correct) values ($1,$2,'r','t','question',true)`, [gs, gone]);
await q(`select public.purge_org($1)`, [gone]);
const left = await one(`select (select count(*) from public.quiz_progress where user_id=$1)::int q, (select count(*) from public.lesson_progress where user_id=$1)::int l, (select count(*) from public.task_attempts where user_id=$1)::int t`, [gs]);
check("quiz, lesson progress and task attempts removed", left.q === 0 && left.l === 0 && left.t === 0, JSON.stringify(left));

group("P4-12 lapsed_students");
const lap = await signup("lap@p4.test", { org_code: "CODEAAAA" });
await q(`insert into public.quiz_progress (user_id, quiz_slug, org_id, xp_earned, last_completed_at, first_completed_at) values ($1,'q9',$2,5, now() - interval '30 days', now() - interval '30 days')`, [lap, orgA]);
const lapsed = (await q(`select user_id from public.lapsed_students(7, 14, 200)`)).rows.map(r => r.user_id);
check("quiz activity counts (a quiz-only learner idle 30 days is found)", lapsed.includes(lap));
await q(`update public.quiz_progress set last_completed_at = now() where user_id=$1`, [lap]);
check("…and a learner active today is not", !(await q(`select user_id from public.lapsed_students(7, 14, 200)`)).rows.some(r => r.user_id === lap));

group("P4-17 functions clients must not call");
check("anon/students cannot call recompute_user_xp", await denied(db, stu, `select public.recompute_user_xp('${stu}')`));
check("students cannot call resolve_invitation", await denied(db, stu, `select * from public.resolve_invitation('x')`));

group("P4-18 session_clicks cap");
const ses = (await one(`select id from public.team_sessions limit 1`))?.id;
if (ses) {
  await q(`insert into public.session_clicks (session_id, user_id, event_id, dwell_ms) select $1, $2, 'e', 0 from generate_series(1, 5010)`, [ses, stu]);
  check("at most 5000 clicks kept per player per session", (await one(`select count(*)::int n from public.session_clicks where session_id=$1 and user_id=$2`, [ses, stu])).n === 5000);
} else {
  const tsId = randomUUID();
  const created = await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status) values ($1,$2,$3,'nexacorp','running')`, [tsId, orgA, stu]).then(() => true).catch(e => { console.log("   (team_sessions insert:", e.message, ")"); return false; });
  if (created) {
    await q(`insert into public.session_clicks (session_id, user_id, event_id, dwell_ms) select $1, $2, 'e', 0 from generate_series(1, 5010)`, [tsId, stu]);
    check("at most 5000 clicks kept per player per session", (await one(`select count(*)::int n from public.session_clicks where session_id=$1 and user_id=$2`, [tsId, stu])).n === 5000);
  } else check("session_clicks cap (could not create a session to test)", false);
}

group("P4-21 / P4-22 indexes and foreign keys");
const idx = (await q(`select indexname from pg_indexes where indexname in ('audit_log_actor_idx','session_events_actor_idx')`)).rows.length;
check("audit_log.actor_id + session_events.actor_id indexed", idx === 2);
const fks = (await q(`select conname from pg_constraint where conname in ('quiz_progress_org_id_fkey','lesson_progress_org_id_fkey','session_clicks_user_id_fkey')`)).rows.length;
check("the three missing foreign keys exist", fks === 3);

group("P4-24 team cron jobs idle without a live session");
const cmds = (await q(`select jobname, command from cron.job where jobname in ('team-promote-injects','team-replenish-feed','team-lifecycle-tick')`)).rows;
check("all three frequent jobs are guarded by a live-session check", cmds.length === 3 && cmds.every(c => c.command.includes("where exists (select 1 from public.team_sessions")), JSON.stringify(cmds.map(c => c.jobname)));

group("0081 feed refill keeps the session's pace");
{
  const sid = randomUUID();
  await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status, started_at, feed_gap_ms, feed_jitter_ms)
           values ($1,$2,$3,'nexacorp','running', now() - interval '10 minutes', 30000, 0)`, [sid, orgA, stu]);
  // 8 fired noise logs to recycle, 2 still pending far in the future.
  for (let i = 0; i < 8; i++) {
    await q(`insert into public.session_injects (session_id, due_offset_ms, trigger, channel, body, expected_action, status)
             values ($1, $2, '{"kind":"at_time"}', 'feed', $3, '{"expected_verdict":"benign","origin":"noise"}', 'fired')`,
      [sid, i * 30000, JSON.stringify({ id: `n${i}`, description: "noise" })]);
  }
  const lastPending = 20 * 60 * 1000;
  await q(`insert into public.session_injects (session_id, due_offset_ms, trigger, channel, body, status) values
           ($1, $2, '{"kind":"at_time"}', 'feed', '{"id":"p1"}', 'pending'), ($1, $3, '{"kind":"at_time"}', 'feed', '{"id":"p2"}', 'pending')`,
    [sid, lastPending - 60000, lastPending]);
  const added = (await one(`select public.replenish_feed() as n`)).n;
  const refill = (await q(`select due_offset_ms from public.session_injects where session_id=$1 and status='pending' and body->>'id' not in ('p1','p2') order by due_offset_ms`, [sid])).rows.map(r => Number(r.due_offset_ms));
  check("the refill added recycled noise", added >= 1 && refill.length === added, `added ${added}`);
  check("refill starts after the last pending log (no overlap)", refill.length > 0 && refill[0] >= lastPending + 30000, `first ${refill[0]}`);
  const gaps = refill.slice(1).map((v, i) => v - refill[i]);
  check("refill spaced at the session's pace (30 s), not 3–7 s", gaps.every(g => g >= 30000), JSON.stringify(gaps));
}

group("P4-01 export sort columns exist in the schema");
const src = fs.readFileSync(new URL("../src/app/api/superadmin/orgs/[id]/export/route.ts", import.meta.url), "utf8");
const pairs = [...src.matchAll(/by(?:Org|Members)\("(\w+)",\s*(?:"[^"]*",\s*)?\[([^\]]*)\]/g)].map(m => [m[1], [...m[2].matchAll(/"(\w+)"/g)].map(x => x[1])]);
check("found the export's table/sort-column list", pairs.length >= 8, String(pairs.length));
for (const [table, cols] of pairs) {
  const have = new Set((await q(`select column_name from information_schema.columns where table_schema='public' and table_name=$1`, [table])).rows.map(r => r.column_name));
  const missing = cols.filter(c => !have.has(c));
  check(`export sorts ${table} by existing columns (${cols.join(", ")})`, missing.length === 0, missing.length ? `missing: ${missing.join(", ")}` : "");
}

console.log(`\n${fail === 0 ? "\x1b[32mPASS" : "\x1b[31mFAIL"}\x1b[0m — ${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.map(f => "  • " + f).join("\n")); process.exit(1); }
