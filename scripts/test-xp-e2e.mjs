// XP end-to-end (DB level): every XP-bearing write is server-only and the
// server path credits exactly the pre-defined points, marks completion, and the
// student's profiles.xp reflects it. Runs every migration in PGlite.
//
// Run: node scripts/test-xp-e2e.mjs   (no Docker / Supabase needed)
import { randomUUID } from "node:crypto";
import { freshDb, asUser } from "./lib/pgliteHarness.mjs";

let pass = 0, fail = 0; const failures = [];
function check(name, cond, extra = "") {
  if (cond) pass++; else { fail++; failures.push(name + (extra ? ` — ${extra}` : "")); }
  console.log(`  ${cond ? "✅" : "❌"} ${name}${extra ? `  (${extra})` : ""}`);
}
const group = t => console.log(`\n\x1b[1m${t}\x1b[0m`);
async function denied(db, uid, sql) {
  try { await asUser(db, uid, () => db.query(sql)); return false; }
  catch (e) { return /permission denied|violates row-level security/i.test(String(e.message)); }
}

const { db, q, one } = await freshDb();

// ── A student enrolled through a class code (the real signup path) ─────────
const org = randomUUID();
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'XP College','xp-college',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'XPCODE01', now() + interval '1 day')`, [org]);
const uid = randomUUID();
await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,'student@xp.test','{"org_code":"XPCODE01","full_name":"Stu Dent"}')`, [uid]);
const xpOf = async () => Number((await one(`select xp from public.profiles where id=$1`, [uid])).xp);

group("Setup");
check("student profile created by signup trigger", !!(await one(`select id from public.profiles where id=$1`, [uid])));
check("student is an active member of the college", !!(await one(`select 1 from public.org_members where user_id=$1 and org_id=$2 and status='active'`, [uid, org])));
check("starts at 0 XP", (await xpOf()) === 0);

group("Client (signed-in student) can NOT write any XP source");
check("INSERT room_progress denied (AUTH-002)", await denied(db, uid, `insert into public.room_progress (user_id, room_id, org_id, xp_earned) values ('${uid}','fake-room','${org}',1000)`));
check("UPDATE room_progress denied", await denied(db, uid, `update public.room_progress set xp_earned = 1000 where user_id = '${uid}'`));
check("UPDATE task_attempts denied (source of room XP)", await denied(db, uid, `update public.task_attempts set xp_awarded = 999 where user_id = '${uid}'`));
check("INSERT task_attempts denied", await denied(db, uid, `insert into public.task_attempts (user_id, room_id, task_id, task_type, correct, xp_awarded) values ('${uid}','r','t','question',true,999)`));
check("graded_first_answers not readable/writable by clients", await denied(db, uid, `select * from public.graded_first_answers`));
check("record_room_task not executable by clients", await denied(db, uid, `select * from public.record_room_task('${uid}', null, 'r', 't', 999, array['t'], '{}'::jsonb, 0.65)`));
check("INSERT scenario_history denied", await denied(db, uid, `insert into public.scenario_history (user_id, slug, xp_earned) values ('${uid}','s',2000)`));
check("INSERT quiz_progress denied", await denied(db, uid, `insert into public.quiz_progress (user_id, quiz_slug, xp_earned) values ('${uid}','q',500)`));
check("INSERT lesson_progress denied", await denied(db, uid, `insert into public.lesson_progress (user_id, lesson_key, xp_earned) values ('${uid}','l',500)`));
// profiles.xp: the update may be accepted by RLS but the guard must keep xp server-owned.
try { await asUser(db, uid, () => db.query(`update public.profiles set xp = 99999 where id = '${uid}'`)); } catch { /* denied is fine too */ }
check("profiles.xp cannot be set by the student", (await xpOf()) === 0, `xp=${await xpOf()}`);

group("Server path (service role) credits the pre-defined points");
await q(`set role service_role`);
const room = "xp-room", tasks = ["q1", "q2", "read1"], gradeable = { q1: 20, q2: 30 };
const rec = async (task, xp, telemetry = null) =>
  (await q(`select * from public.record_room_task($1,$2,$3,$4,$5,$6,$7,0.65,$8)`,
    [uid, org, room, task, xp, tasks, JSON.stringify(gradeable), telemetry ? JSON.stringify(telemetry) : null])).rows[0];

let r = await rec("q1", 20, { taskId: "q1", ms: 1200 });
check("task q1 credited its 20 XP", r.task_xp === 20 && r.room_xp === 20, JSON.stringify(r));
check("room not complete yet", r.room_completed_at === null && r.newly_completed === false);
check("profiles.xp = 20 (recomputed)", (await xpOf()) === 20, `xp=${await xpOf()}`);

r = await rec("q1", 10);
check("a lower later score never lowers the best (still 20)", r.task_xp === 20 && r.room_xp === 20, JSON.stringify(r));

r = await rec("read1", 5);
check("reading task credited its 5 XP", r.task_xp === 5 && r.room_xp === 25, JSON.stringify(r));
check("still not complete (q2 not done)", r.room_completed_at === null);

r = await rec("q2", 30);
check("q2 credited 30 → room XP 55", r.task_xp === 30 && r.room_xp === 55, JSON.stringify(r));
check("room completed on the last task (score 50/50 ≥ 65%)", r.room_completed_at !== null && r.newly_completed === true);
check("profiles.xp = 55", (await xpOf()) === 55, `xp=${await xpOf()}`);

r = await rec("q2", 30);
check("repeating a completion is idempotent (no double credit)", r.room_xp === 55 && r.newly_completed === false && (await xpOf()) === 55);

const row = await one(`select completed_task_ids, per_task_xp, telemetry from public.room_progress where user_id=$1 and room_id=$2`, [uid, room]);
check("completed_task_ids recorded", JSON.stringify([...row.completed_task_ids].sort()) === JSON.stringify(["q1", "q2", "read1"]), JSON.stringify(row.completed_task_ids));
check("telemetry appended", Array.isArray(row.telemetry) && row.telemetry.length === 1);

group("Pass rule: all tasks done but score below 65% → not completed, XP still kept");
const room2 = "xp-room-2";
const rec2 = async (task, xp) => (await q(`select * from public.record_room_task($1,$2,$3,$4,$5,$6,$7,0.65)`,
  [uid, org, room2, task, xp, ["a", "b"], JSON.stringify({ a: 20, b: 20 })])).rows[0];
await rec2("a", 20);
r = await rec2("b", 5);
check("25/40 = 62.5% → not completed", r.room_completed_at === null, JSON.stringify(r));
check("the 25 XP earned is still credited", r.room_xp === 25 && (await xpOf()) === 80, `xp=${await xpOf()}`);
r = await rec2("b", 20);
check("improving b to full → completes (40/40)", r.room_completed_at !== null && r.newly_completed === true && (await xpOf()) === 95);

group("First graded answer per question sticks");
await q(`insert into public.graded_first_answers (user_id, kind, content_id, question_id, answer, correct) values ($1,'quiz','qz','q1','1',false) on conflict do nothing`, [uid]);
await q(`insert into public.graded_first_answers (user_id, kind, content_id, question_id, answer, correct) values ($1,'quiz','qz','q1','0',true) on conflict do nothing`, [uid]);
const fa = await one(`select correct, answer from public.graded_first_answers where user_id=$1 and kind='quiz' and content_id='qz' and question_id='q1'`, [uid]);
check("a later correct resubmission does not replace the first (wrong) answer", fa.correct === false, JSON.stringify(fa));
await q(`reset role`);

group("Org quiz answer keys never reach the browser (AUTH-009)");
const quizContent = { title: "Org quiz", questions: [
  { id: "a", prompt: "p1", options: ["x", "y"], answer: 1, explanation: "because", xp: 10 },
  { id: "b", prompt: "p2", options: ["x", "y"], answer: 0, explanation: "since", xp: 10 },
] };
const otherOrg = randomUUID();
await q(`insert into public.organizations (id, name) values ($1, 'Other college') on conflict do nothing`, [otherOrg]).catch(() => {});
await q(`insert into public.content_quizzes (id, org_id, status, content) values ('org-qz-1', $1, 'published', $2)`, [org, JSON.stringify(quizContent)]);
await q(`insert into public.content_quizzes (id, org_id, status, content) values ('org-qz-other', $1, 'published', $2)`, [otherOrg, JSON.stringify(quizContent)]).catch(() => {});
check("student cannot SELECT content_quizzes.content (the key)", await denied(db, uid, `select content from public.content_quizzes`));
const listed = await asUser(db, uid, () => db.query(`select id, title from public.content_quizzes`), { org_id: org });
check("student can still list quiz ids/titles", listed.rows.some(r => r.id === "org-qz-1"), JSON.stringify(listed.rows));
const safe = await asUser(db, uid, () => db.query(`select id, content from public.published_quizzes()`), { org_id: org });
const safeRow = safe.rows.find(r => r.id === "org-qz-1");
const safeQs = safeRow?.content?.questions ?? [];
check("published_quizzes() returns the college's quiz", !!safeRow && safeQs.length === 2, JSON.stringify(safe.rows.map(r => r.id)));
check("published_quizzes() strips answer + explanation", safeQs.every(x => !("answer" in x) && !("explanation" in x)) && safeQs[0]?.prompt === "p1" && safeQs[0]?.xp === 10, JSON.stringify(safeQs[0]));
check("published_quizzes() hides other colleges' quizzes", !safe.rows.some(r => r.id === "org-qz-other"));
const full = await one(`select content from public.content_quizzes where id='org-qz-1'`);
check("server (service role) still reads the full key for grading", full.content.questions[0].answer === 1);

console.log(`\n${fail === 0 ? "\x1b[32mPASS" : "\x1b[31mFAIL"}\x1b[0m — ${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.map(f => "  • " + f).join("\n")); process.exit(1); }
