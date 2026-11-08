// Team Training 0104: no automatic pause, presence notices, scheduled end, the active-time
// reaper with a warning, isolation by approval, and an isolated host leaving the feed.
// Runs every migration in PGlite (no Docker / Supabase needed).
//
// Run: node scripts/test-0104-db.mjs
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
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-0104',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODE0104', now() + interval '1 day')`, [org]);
const signup = async email => { const id = randomUUID(); await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [id, email, JSON.stringify({ org_code: "CODE0104" })]); return id; };
const [t1, t2, t3, t3b, mgr, ins] = [await signup("t1@x.test"), await signup("t2@x.test"), await signup("t3@x.test"), await signup("t3b@x.test"), await signup("mgr@x.test"), await signup("ins@x.test")];
// 0106: the instructor seat is held only by an organization admin (or the platform owner).
await q(`update public.org_members set role = 'org_admin' where org_id = $1 and user_id = $2`, [org, ins]);

async function newSession(seats, extra = "") {
  const id = randomUUID();
  await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status, schema_version, started_at ${extra ? ", " + extra.split("=")[0] : ""}) values ($1,$2,$3,'nexacorp','running',2, now() - interval '10 minutes' ${extra ? ", " + extra.split("=")[1] : ""})`, [id, org, ins]);
  for (const [u, r] of seats) await q(`insert into public.team_session_members (session_id, user_id, role, status, last_seen_at) values ($1,$2,$3,'active', now())`, [id, u, r]);
  await q(`insert into public.session_events (session_id, seq, type, payload, occurred_at) values ($1, 1, 'session.started', '{}', now() - interval '10 minutes')`, [id]);
  return id;
}
async function asUserCommit(uid, fn) {
  await db.exec("begin");
  try {
    await db.exec(`set local role authenticated; select set_config('request.jwt.claims', '${JSON.stringify({ sub: uid, role: "authenticated", org_id: org })}', true);`);
    const r = await fn(); await db.exec("commit"); return r;
  } catch (e) { await db.exec("rollback"); throw e; }
}
let n = 0;
async function act(ses, uid, type, payload) {
  try {
    const r = await asUserCommit(uid, () => db.query(`select (public.apply_session_action(p_session => $1, p_type => $2, p_payload => $3::jsonb, p_idempotency_key => $4)).seq as seq`, [ses, type, JSON.stringify(payload), `k${++n}`]));
    return { seq: Number(r.rows[0]?.seq), err: null };
  } catch (e) { return { seq: null, err: String(e.message) }; }
}
const evs = async (ses, type) => (await q(`select seq, type, actor_id, role, payload from public.session_events where session_id=$1 and type=$2 order by seq`, [ses, type])).rows;

// ── 1. no automatic pause ────────────────────────────────────────────────────
group("1. pauses are human-only");
{
  const s = await newSession([[t1, "t1"], [t2, "t2"], [ins, "instructor"]]);
  const auto = (await one(`select public.team_transition($1,'paused','coverage',null,'x') r`, [s])).r;
  check("team_transition refuses a coverage pause", auto.noop === true && auto.refused === "automatic_pause_disabled", JSON.stringify(auto));
  const owner = (await one(`select public.team_transition($1,'paused','owner_left',null,null) r`, [s])).r;
  check("team_transition refuses an owner_left pause", owner.refused === "automatic_pause_disabled");
  check("the session is still running", (await one(`select status from public.team_sessions where id=$1`, [s])).status === "running");
  const man = (await one(`select public.team_transition($1,'paused','manual',$2,null) r`, [s, ins])).r;
  check("a manual pause works", man.ok === true && !man.noop && man.type === "session.paused");
  await q(`update public.team_sessions set paused_at = now() - interval '30 seconds' where id=$1`, [s]);
  const end = (await one(`select public.team_transition($1,'ended','manual',$2,null) r`, [s, ins])).r;
  const row = await one(`select status, paused_ms from public.team_sessions where id=$1`, [s]);
  check("ending while paused closes the open pause into paused_ms", end.type === "session.ended" && Number(row.paused_ms) >= 29000, `paused_ms=${row.paused_ms}`);
}

group("1b. the lifecycle tick raises notices, never pauses, and lifts a leftover auto pause");
{
  const s = await newSession([[t1, "t1"], [t2, "t2"], [ins, "instructor"]]);
  await q(`update public.team_sessions set staff_seen_at = now() - interval '10 minutes' where id=$1`, [s]);
  await q(`update public.team_session_members set last_seen_at = now() - interval '10 minutes' where session_id=$1 and role in ('instructor','t1')`, [s]);
  await q(`select public.team_lifecycle_tick()`); await q(`select public.team_lifecycle_tick()`);
  const st = await one(`select status, presence_notice from public.team_sessions where id=$1`, [s]);
  check("instructor gone: still running", st.status === "running");
  const notes = await evs(s, "presence.notice");
  check("one owner_left notice raised", notes.length === 1 && notes[0].payload.kind === "owner_left" && notes[0].payload.state === "raised", JSON.stringify(notes.map(x => x.payload)));
  await q(`select public.team_lifecycle_tick()`);
  check("no duplicate notice on the next tick", (await evs(s, "presence.notice")).length === 1);
  await q(`update public.team_sessions set staff_seen_at = now() where id=$1`, [s]);
  await q(`select public.team_lifecycle_tick()`); await q(`select public.team_lifecycle_tick()`);
  const n2 = (await evs(s, "presence.notice")).map(x => `${x.payload.kind}:${x.payload.state}`);
  check("owner back: owner_left cleared, Tier-1 coverage raised", n2.join(",") === "owner_left:raised,owner_left:cleared,coverage:raised", n2.join(","));
  check("coverage notice names the missing seat", JSON.stringify((await evs(s, "presence.notice"))[2]?.payload.missing) === '["t1"]');
  check("no session.paused at any point", (await evs(s, "session.paused")).length === 0);

  const s2 = await newSession([[t1, "t1"], [t2, "t2"], [ins, "instructor"]]);
  await q(`update public.team_sessions set status='paused', pause_reason='coverage', paused_at=now() - interval '20 seconds' where id=$1`, [s2]);
  await q(`select public.team_lifecycle_tick()`);
  check("a leftover coverage pause is resumed by the tick", (await one(`select status from public.team_sessions where id=$1`, [s2])).status === "running");
}

// ── 2. reaper on active time ────────────────────────────────────────────────
group("2. the 4-hour reaper counts active time and warns first");
{
  const s = await newSession([[t1, "t1"], [ins, "instructor"]]);
  // 5 h of wall clock, 2 h of it paused: 3 h active. Not reaped, not warned.
  await q(`update public.team_sessions set started_at = now() - interval '5 hours', paused_ms = 7200000 where id=$1`, [s]);
  await q(`insert into public.session_events (session_id, seq, actor_id, role, type, payload) values ($1, 2, $2, 't1', 'note.added', '{"text":"x"}')`, [s, t1]);
  await q(`select public.reap_stale_team_sessions()`);
  let row = await one(`select status, reap_warned_at from public.team_sessions where id=$1`, [s]);
  check("3 h active of 5 h wall: kept, no warning", row.status === "running" && row.reap_warned_at == null);
  await q(`update public.team_sessions set paused_ms = 0 where id=$1`, [s]);   // now 5 h active
  await q(`select public.reap_stale_team_sessions()`);
  row = await one(`select status, reap_warned_at from public.team_sessions where id=$1`, [s]);
  const warn = await evs(s, "session.reap_warning");
  check("over the cap: warned first, not ended in the same run", row.status === "running" && row.reap_warned_at != null && warn.length === 1 && warn[0].payload.reason === "active_cap", JSON.stringify({ row, warn: warn.map(w => w.payload) }));
  await q(`update public.team_sessions set reap_warned_at = now() - interval '5 minutes' where id=$1`, [s]);
  await q(`select public.reap_stale_team_sessions()`);
  check("ended once the warning is 4+ minutes old", (await one(`select status from public.team_sessions where id=$1`, [s])).status === "ended");
}

// ── 3. scheduled end ────────────────────────────────────────────────────────
group("3. end in 2 minutes, kept by the server");
{
  const s = await newSession([[t1, "t1"], [ins, "instructor"]]);
  const r = (await one(`select public.team_schedule_end($1,$2,120000) r`, [s, ins])).r;
  check("scheduled with an ends_at", r.ok === true && !!r.ends_at);
  const again = (await one(`select public.team_schedule_end($1,$2,120000) r`, [s, ins])).r;
  check("scheduling again is a noop returning the same time", again.noop === true && again.ends_at === r.ends_at);
  check("session.end_scheduled appended", (await evs(s, "session.end_scheduled")).length === 1);
  await q(`select public.team_lifecycle_tick()`);
  check("not ended before ends_at", (await one(`select status from public.team_sessions where id=$1`, [s])).status === "running");
  await q(`update public.team_sessions set end_at = now() - interval '1 second' where id=$1`, [s]);
  await q(`select public.team_lifecycle_tick()`);
  const ended = await evs(s, "session.ended");
  check("the tick ends it at ends_at, reason scheduled", ended.length === 1 && ended[0].payload.reason === "scheduled");

  const s2 = await newSession([[t1, "t1"], [ins, "instructor"]]);
  await q(`select public.team_schedule_end($1,$2,120000)`, [s2, ins]);
  const c = (await one(`select public.team_cancel_end($1,$2) r`, [s2, ins])).r;
  check("cancel clears it", c.ok === true && (await one(`select end_at from public.team_sessions where id=$1`, [s2])).end_at == null && (await evs(s2, "session.end_cancelled")).length === 1);
}

// ── 4. isolation by approval ────────────────────────────────────────────────
group("4. isolation needs the shift senior");
{
  const s = await newSession([[t1, "t1"], [t2, "t2"], [t3, "t3"], [mgr, "mgr"], [ins, "instructor"]]);
  const direct = await act(s, t2, "edr.host_isolated", { host: "WS-ACC-4477" });
  check("Tier-2 can no longer isolate directly", /action_not_allowed/.test(direct.err ?? ""), direct.err ?? "accepted");
  const t1req = await act(s, t1, "isolation.requested", { host: "WS-ACC-4477", reason: "shell" });
  check("Tier-1 cannot request an isolation", /action_not_allowed/.test(t1req.err ?? ""), t1req.err ?? "accepted");
  const noReason = await act(s, t2, "isolation.requested", { host: "WS-ACC-4477" });
  check("a request needs a reason", /invalid_payload/.test(noReason.err ?? ""), noReason.err ?? "accepted");
  const req = await act(s, t2, "isolation.requested", { host: "WS-ACC-4477", reason: "reverse shell to 104.248.93.41", incident: "case-1" });
  check("Tier-2 requests an isolation", req.err === null && req.seq > 0, req.err ?? "");
  const dup = await act(s, t3, "isolation.requested", { host: "ws-acc-4477", reason: "same host" });
  check("a second open request on the host is refused", /isolation_pending/.test(dup.err ?? ""), dup.err ?? "accepted");
  const selfOk = await act(s, t2, "isolation.approved", { request_seq: req.seq });
  check("the requester cannot approve (role gate)", /action_not_allowed|not_approver/.test(selfOk.err ?? ""), selfOk.err ?? "accepted");
  const t3ok = await act(s, t3, "isolation.approved", { request_seq: req.seq });
  check("Tier-3 cannot approve while an active Manager is seated", /not_approver/.test(t3ok.err ?? ""), t3ok.err ?? "accepted");
  check("nothing isolated yet", (await evs(s, "edr.host_isolated")).length === 0);
  const ok = await act(s, mgr, "isolation.approved", { request_seq: req.seq });
  check("the Manager approves", ok.err === null, ok.err ?? "");
  const iso = await evs(s, "edr.host_isolated");
  check("the server recorded edr.host_isolated, actor = requester", iso.length === 1 && iso[0].actor_id === t2 && iso[0].payload.approved_by === mgr && iso[0].payload.request_seq === req.seq, JSON.stringify(iso[0]?.payload));
  const status = (await evs(s, "feed.event")).filter(e => e.payload.kind === "containment_status");
  check("one EDR containment status row", status.length === 1 && status[0].payload.hostname === "WS-ACC-4477" && status[0].payload.containment === "contained");
  const twice = await act(s, ins, "isolation.approved", { request_seq: req.seq });
  check("an answered request cannot be answered again", /no_open_request/.test(twice.err ?? ""), twice.err ?? "accepted");
  const again = await act(s, t3, "isolation.requested", { host: "WS-ACC-4477", reason: "again" });
  check("requesting an isolated host is refused", /already_isolated/.test(again.err ?? ""), again.err ?? "accepted");

  // Manager offline → Tier-3 (not the requester) approves; the requesting Tier-3 cannot.
  await q(`update public.team_session_members set last_seen_at = now() - interval '10 minutes' where session_id=$1 and role='mgr'`, [s]);
  const r2 = await act(s, t3, "isolation.requested", { host: "WS-HR-1182", reason: "keylogger helper" });
  const selfT3 = await act(s, t3, "isolation.approved", { request_seq: r2.seq });
  check("a Tier-3 requester cannot approve their own request", /not_approver/.test(selfT3.err ?? ""), selfT3.err ?? "accepted");
  const den = await act(s, ins, "isolation.denied", { request_seq: r2.seq, reason: "wait for memory capture" });
  check("staff may always answer (override): deny", den.err === null, den.err ?? "");
  check("a denial isolates nothing", (await evs(s, "edr.host_isolated")).length === 1);

  // Release stays direct, by the Manager too, and posts a status row.
  const rel = await act(s, mgr, "edr.host_released", { host: "WS-ACC-4477" });
  check("the Manager releases directly", rel.err === null, rel.err ?? "");
  const lifted = (await evs(s, "feed.event")).filter(e => e.payload.containment === "released");
  check("a containment-lifted status row", lifted.length === 1);

  // Approver tiers with no Manager seated.
  const s3 = await newSession([[t2, "t2"], [t3, "t3"], [t3b, "t3"], [ins, "instructor"]]);
  const r3 = await act(s3, t3, "isolation.requested", { host: "SRV-DB-01", reason: "beacon" });
  const byT3b = await act(s3, t3b, "isolation.approved", { request_seq: r3.seq });
  check("no Manager: another active Tier-3 approves", byT3b.err === null, byT3b.err ?? "");
  const s4 = await newSession([[t2, "t2"], [ins, "instructor"]]);
  const r4 = await act(s4, t2, "isolation.requested", { host: "SRV-DB-02", reason: "beacon" });
  const byIns = await act(s4, ins, "isolation.approved", { request_seq: r4.seq });
  check("no Manager, no other Tier-3: the instructor approves", byIns.err === null, byIns.err ?? "");
  const canFn = (await one(`select has_function_privilege('authenticated', 'public.team_isolation_can_approve(uuid,uuid,uuid)', 'execute') as can`)).can;
  check("clients cannot call the approver function", canFn === false);
}

// ── 5. an isolated host leaves the feed ──────────────────────────────────────
group("5. promote skips rows about an isolated host");
{
  const s = await newSession([[t2, "t2"], [mgr, "mgr"], [ins, "instructor"]]);
  const add = (body, due = 0) => q(`insert into public.session_injects (session_id, due_offset_ms, channel, body, status) values ($1,$2,'feed',$3,'pending')`, [s, due, JSON.stringify(body)]);
  await add({ id: "a1", hostname: "WS-ACC-4477", src_ip: "10.10.20.241", dst_ip: "104.248.93.41" });
  await q(`select public.promote_due_injects()`);
  const req = await act(s, t2, "isolation.requested", { host: "WS-ACC-4477", reason: "shell" });
  await act(s, mgr, "isolation.approved", { request_seq: req.seq });
  const iso = (await evs(s, "edr.host_isolated"))[0];
  check("the isolation carries the host's address", JSON.stringify(iso?.payload.ips) === '["10.10.20.241"]', JSON.stringify(iso?.payload.ips));
  await add({ id: "a2", hostname: "ws-acc-4477", src_ip: "10.10.20.241", dst_ip: "91.215.85.140" });
  await add({ id: "a3", hostname: "SRV-FW-01", src_ip: "10.10.20.241", dst_ip: "91.215.85.140" });
  await add({ id: "a4", hostname: "SRV-DC-01", src_ip: "10.10.1.5", dst_ip: "10.10.20.241" });
  await add({ id: "b1", hostname: "WS-HR-1182", src_ip: "10.10.30.12", dst_ip: "85.209.11.37" });
  await q(`insert into public.session_injects (session_id, due_offset_ms, channel, body, status) values ($1,0,'inject','{"kind":"twist","text":"WS-ACC-4477 calls a new C2"}','pending')`, [s]);
  await q(`select public.promote_due_injects()`);
  const fired = (await evs(s, "feed.event")).map(e => e.payload.id).filter(x => !String(x).startsWith("iso-"));
  check("only the row about another host fired", JSON.stringify(fired) === '["a1","b1"]', JSON.stringify(fired));
  const skipped = (await q(`select body->>'id' id, skip_reason from public.session_injects where session_id=$1 and status='skipped' order by body->>'id'`, [s])).rows;
  check("hostname, source and destination matches are skipped and marked", skipped.length === 3 && skipped.every(r => /^isolated:/.test(r.skip_reason)), JSON.stringify(skipped));
  check("a message inject about the host still fires", (await evs(s, "staff.inject")).length === 1);
  await act(s, t2, "edr.host_released", { host: "WS-ACC-4477" });
  await add({ id: "a5", hostname: "WS-ACC-4477", src_ip: "10.10.20.241", dst_ip: "8.8.8.8" });
  await q(`select public.promote_due_injects()`);
  check("a release brings the host back", (await evs(s, "feed.event")).some(e => e.payload.id === "a5"));
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.map(f => `  - ${f}`).join("\n")); process.exit(1); }
