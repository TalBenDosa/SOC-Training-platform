#!/usr/bin/env node
/**
 * One-command local Supabase for development / demo.
 *
 * PREREQUISITE (one-time, manual): install Docker Desktop and make sure it's
 * running — https://www.docker.com/products/docker-desktop/ . That's the only
 * thing this script can't do for you; everything below is automated.
 *
 * What it does:
 *   1. `supabase init` (creates config.toml if missing; keeps your migrations)
 *   2. `supabase start`  → boots local Postgres+Auth+Studio AND applies every
 *      file in supabase/migrations/ in order (0001 → 0002 → 0003)
 *   3. reads the local keys and writes them into .env.local (merging, never
 *      clobbering your other env vars like ANTHROPIC_API_KEY)
 *
 * Then just restart `npm run dev` — signup/login are live against the local DB.
 * Tear down later with:  npx supabase stop
 */
import { execSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = process.cwd();
const run = (cmd, opts = {}) => execSync(cmd, { stdio: "inherit", ...opts });
const capture = (cmd) => execSync(cmd, { stdio: ["ignore", "pipe", "ignore"] }).toString();

function fail(msg) {
  console.error(`\n❌ ${msg}\n`);
  process.exit(1);
}

// ── 0. Docker check ──────────────────────────────────────────────────────────
try {
  execSync("docker ps", { stdio: "ignore" });
} catch {
  fail(
    "Docker isn't running. Local Supabase needs Docker Desktop.\n" +
    "   1) Install: https://www.docker.com/products/docker-desktop/\n" +
    "   2) Start Docker Desktop and wait for it to say 'running'\n" +
    "   3) Re-run: npm run supabase:local\n\n" +
    "   (Prefer no Docker? Use a free cloud project instead — see INFRASTRUCTURE.md.)",
  );
}

const SUPABASE = "npx --yes supabase@latest";

// ── 1. init (only if config missing — never touches existing migrations) ────────
if (!existsSync(resolve(root, "supabase/config.toml"))) {
  console.log("→ Initializing Supabase config…");
  try { run(`${SUPABASE} init`); } catch { /* may already be partially set up */ }
}

// ── 2. start (applies all migrations) ───────────────────────────────────────────
console.log("→ Starting local Supabase (first run pulls Docker images — a few minutes)…");
run(`${SUPABASE} start`);

// ── 3. read keys and write .env.local ────────────────────────────────────────────
console.log("→ Reading local credentials…");
let statusEnv = "";
try { statusEnv = capture(`${SUPABASE} status -o env`); }
catch { fail("Could not read `supabase status`. Is the stack up? Try: npx supabase status"); }

const parsed = {};
for (const line of statusEnv.split("\n")) {
  const m = line.match(/^([A-Z_]+)="?(.*?)"?$/);
  if (m) parsed[m[1]] = m[2];
}

const mapping = {
  NEXT_PUBLIC_SUPABASE_URL: parsed.API_URL,
  NEXT_PUBLIC_SUPABASE_ANON_KEY: parsed.ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY: parsed.SERVICE_ROLE_KEY,
  DATABASE_URL: parsed.DB_URL,
};
for (const [k, v] of Object.entries(mapping)) {
  if (!v) fail(`Missing ${k} in supabase status output. Run \`npx supabase status\` and set it manually.`);
}

const envPath = resolve(root, ".env.local");
let lines = existsSync(envPath) ? readFileSync(envPath, "utf8").split("\n") : [];
for (const [key, value] of Object.entries(mapping)) {
  const idx = lines.findIndex((l) => l.startsWith(`${key}=`));
  const entry = `${key}=${value}`;
  if (idx >= 0) lines[idx] = entry;
  else lines.push(entry);
}
writeFileSync(envPath, lines.filter((l, i) => l !== "" || i < lines.length - 1).join("\n").replace(/\n{3,}/g, "\n\n") + "\n");

console.log(`
✅ Local Supabase is up and .env.local is configured.

   Studio (browse tables/users):  ${parsed.STUDIO_URL ?? "http://127.0.0.1:54323"}
   API URL:                       ${mapping.NEXT_PUBLIC_SUPABASE_URL}

   Next:
     1) Restart the dev server:   npm run dev
     2) Open http://localhost:3000/signup  → create an account (works immediately;
        local Supabase auto-confirms emails, no email step)
     3) Tear down when done:      npx supabase stop
`);
