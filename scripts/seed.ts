/**
 * Seed Supabase with platform content (paths, scenarios, badges).
 *
 * Usage:
 *   1. Set SUPABASE_SERVICE_ROLE_KEY and NEXT_PUBLIC_SUPABASE_URL in .env.local
 *   2. Run `npm run seed`
 *
 * Or apply the SQL directly:
 *   psql $DATABASE_URL -f supabase/migrations/0001_init.sql
 *   psql $DATABASE_URL -f supabase/seeds/0001_content.sql
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createClient } from "@supabase/supabase-js";

async function main() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    console.error("Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
    process.exit(1);
  }
  const supabase = createClient(url, key, { auth: { persistSession: false } });

  const root = process.cwd();
  const migration = readFileSync(join(root, "supabase/migrations/0001_init.sql"), "utf8");
  const seed = readFileSync(join(root, "supabase/seeds/0001_content.sql"), "utf8");

  console.log("Applying migration…");
  // Supabase JS doesn't run multi-statement SQL natively; you'll typically use
  // the Supabase CLI or psql. This script is a convenience wrapper for envs
  // where the `pg` HTTP RPC is enabled.
  for (const stmt of split(migration)) {
    const { error } = await supabase.rpc("exec_sql", { sql: stmt }).catch(e => ({ error: e }));
    if (error) console.warn("[migration] warn:", String(error).slice(0, 200));
  }
  console.log("Seeding content…");
  for (const stmt of split(seed)) {
    const { error } = await supabase.rpc("exec_sql", { sql: stmt }).catch(e => ({ error: e }));
    if (error) console.warn("[seed] warn:", String(error).slice(0, 200));
  }
  console.log("Done.");
}

function split(sql: string): string[] {
  return sql.split(/;\s*\n/g).map(s => s.trim()).filter(s => s && !s.startsWith("--"));
}

main().catch(e => { console.error(e); process.exit(1); });
