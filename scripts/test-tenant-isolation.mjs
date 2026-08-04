// Tenant-isolation acceptance test — the Phase 0 gate.
// ---------------------------------------------------------------------------
// Proves, end-to-end through real signed-in sessions, that a user of org A can
// neither READ nor WRITE org B's rows once 0010+0011 are applied and the
// access-token hook is enabled. This is the test that must pass before the
// multi-tenant build can be sold.
//
// Requires a MIGRATED Supabase (staging): env NEXT_PUBLIC_SUPABASE_URL,
// NEXT_PUBLIC_SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY. Skips (exit 0) if
// they are absent, so it is safe in CI where secrets aren't set.
//
// Run: node scripts/test-tenant-isolation.mjs
import { createClient } from "@supabase/supabase-js";

const URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const ANON = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!URL || !ANON || !SERVICE) {
  console.log("SKIP tenant-isolation: Supabase env not set (URL/ANON/SERVICE).");
  process.exit(0);
}

const admin = createClient(URL, SERVICE, { auth: { persistSession: false, autoRefreshToken: false } });
const rnd = Math.random().toString(36).slice(2, 8);
const pw = "Test-" + rnd + "-Pw1";
let failures = 0;
const created = { users: [], orgs: [] };

function check(name, cond) {
  console.log(`${cond ? "PASS" : "FAIL"} — ${name}`);
  if (!cond) failures++;
}

async function makeOrg(tag) {
  const { data, error } = await admin
    .from("organizations")
    .insert({ name: `ISO ${tag} ${rnd}`, slug: `iso-${tag}-${rnd}`, status: "active", seat_limit: 100 })
    .select()
    .single();
  if (error) throw new Error(`org ${tag}: ${error.message}`);
  created.orgs.push(data.id);
  return data.id;
}

async function makeUser(orgId, tag) {
  const email = `iso-${tag}-${rnd}@example.com`;
  const { data, error } = await admin.auth.admin.createUser({ email, password: pw, email_confirm: true });
  if (error) throw new Error(`user ${tag}: ${error.message}`);
  const uid = data.user.id;
  created.users.push(uid);
  // The signup trigger auto-joined them to the bootstrap org. Re-home them to
  // the test org so their JWT (via the hook) carries THIS org_id.
  await admin.from("org_members").delete().eq("user_id", uid);
  await admin.from("org_members").insert({ org_id: orgId, user_id: uid, role: "student", status: "active" });
  await admin.from("profiles").update({ org_id: orgId }).eq("id", uid);
  // Seed one owned progress row in this org.
  await admin.from("room_progress").insert({
    user_id: uid, org_id: orgId, room_id: `iso-room-${tag}`, completed_task_ids: [], xp_earned: 10,
  });
  return { uid, email };
}

async function signIn(email) {
  const c = createClient(URL, ANON, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data, error } = await c.auth.signInWithPassword({ email, password: pw });
  if (error) throw new Error(`signin ${email}: ${error.message}`);
  const claims = JSON.parse(Buffer.from(data.session.access_token.split(".")[1], "base64").toString());
  return { client: c, orgClaim: claims.org_id };
}

async function main() {
  const orgA = await makeOrg("A");
  const orgB = await makeOrg("B");
  const userA = await makeUser(orgA, "a");
  const userB = await makeUser(orgB, "b");

  const A = await signIn(userA.email);
  const B = await signIn(userB.email);

  // 0. the hook actually stamped the org claim
  check("A's JWT carries org_id = org A", A.orgClaim === orgA);
  check("B's JWT carries org_id = org B", B.orgClaim === orgB);

  // 1. Each user reads only their own org's rows
  const aRows = await A.client.from("room_progress").select("org_id");
  check("A reads only org A rows", !aRows.error && aRows.data.every(r => r.org_id === orgA) && aRows.data.length >= 1);

  // 2. A cannot READ B's row by id (cross-tenant read blocked)
  const aSeesB = await A.client.from("room_progress").select("user_id").eq("user_id", userB.uid);
  check("A cannot read B's row (cross-tenant SELECT returns empty)", !aSeesB.error && aSeesB.data.length === 0);

  // 3. A cannot WRITE into org B (cross-tenant INSERT rejected by WITH CHECK)
  const aWritesB = await A.client
    .from("room_progress")
    .insert({ user_id: userA.uid, org_id: orgB, room_id: "iso-evil", completed_task_ids: [], xp_earned: 999 });
  check("A cannot write into org B (WITH CHECK rejects)", !!aWritesB.error);

  // 4. A cannot read B's profile
  const aSeesBProfile = await A.client.from("profiles").select("id").eq("id", userB.uid);
  check("A cannot read B's profile", !aSeesBProfile.error && aSeesBProfile.data.length === 0);

  // 5. A cannot change their own org_id (privilege guard)
  await A.client.from("profiles").update({ org_id: orgB }).eq("id", userA.uid);
  const stillA = await admin.from("profiles").select("org_id").eq("id", userA.uid).single();
  check("A cannot move themselves to org B (org_id frozen)", stillA.data.org_id === orgA);
}

async function cleanup() {
  for (const uid of created.users) await admin.auth.admin.deleteUser(uid).catch(() => {});
  for (const org of created.orgs) await admin.from("organizations").delete().eq("id", org).catch(() => {});
}

main()
  .catch(e => { console.error("ERROR:", e.message); failures++; })
  .finally(async () => {
    await cleanup();
    console.log(failures === 0 ? "\n✅ tenant isolation: ALL CHECKS PASSED" : `\n❌ tenant isolation: ${failures} FAILURE(S)`);
    process.exit(failures === 0 ? 0 : 1);
  });
