/**
 * Adds the three Resend DNS records to hackthesoc.app via the Vercel API, so
 * the DNS side needs no dashboard clicks either.
 *
 * Reads VERCEL_TOKEN (and optional VERCEL_TEAM_ID) from the environment or
 * .env.local. Create a token at Vercel → Account Settings → Tokens. NOTE: if
 * the team enforces SAML SSO, API tokens may be rejected (403) until authorized
 * — in that case fall back to entering the records by hand in the dashboard.
 *
 * Usage:
 *   node scripts/vercel-dns-add.mjs         # list existing records + add the 3 Resend ones (idempotent)
 */
import fs from "node:fs";
import path from "node:path";

const DOMAIN = "hackthesoc.app";
const API = "https://api.vercel.com";

function fromEnvFile(name) {
  if (process.env[name]?.trim()) return process.env[name].trim();
  const p = path.join(process.cwd(), ".env.local");
  if (fs.existsSync(p)) {
    for (const line of fs.readFileSync(p, "utf8").split(/\r?\n/)) {
      const m = line.match(new RegExp(`^\\s*${name}\\s*=\\s*(.+?)\\s*$`));
      if (m) return m[1].replace(/^["']|["']$/g, "").trim();
    }
  }
  return null;
}

const TOKEN = fromEnvFile("VERCEL_TOKEN");
let TEAM = fromEnvFile("VERCEL_TEAM_ID");
if (!TOKEN) {
  console.error(
    "VERCEL_TOKEN not found.\n" +
    "Add it to .env.local:\n  VERCEL_TOKEN=xxxxxxxx\n" +
    "Create it at Vercel → Account Settings → Tokens (scope: your team / Full)."
  );
  process.exit(1);
}

const qs = () => (TEAM ? `?teamId=${encodeURIComponent(TEAM)}` : "");

async function api(method, pathname, body) {
  const res = await fetch(API + pathname + (pathname.includes("?") ? "" : qs()), {
    method,
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  return { ok: res.ok, status: res.status, json };
}

// The three records Resend requires (from `resend-domain-setup.mjs add`).
const RECORDS = [
  { type: "TXT", name: "resend._domainkey",
    value: "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnrtjT3jR2SDkXXnAfji0anlAvwTFwjWF3moFnSjR9dqjzCDxGYw/qKGJ1vSn7Lb+jONigLyTtyaY7I+echkJvc5IT/ySbIn8ftRbeOFKhIZcus25iIlbSCOnAhXbQtmPR/7CsPM8PebA1llrLEmv1q9VSAUTrf0h+M0EPEZXjCQIDAQAB",
    ttl: 60 },
  { type: "MX", name: "send", value: "feedback-smtp.us-east-1.amazonses.com", mxPriority: 10, ttl: 60 },
  { type: "TXT", name: "send", value: "v=spf1 include:amazonses.com ~all", ttl: 60 },
];

(async () => {
  // If no explicit team id, discover whether the domain sits under a team.
  if (!TEAM) {
    const d = await api("GET", `/v5/domains/${DOMAIN}`);
    if (d.ok && d.json?.domain?.teamId) { TEAM = d.json.domain.teamId; console.log(`Detected teamId: ${TEAM}`); }
    else if (d.status === 403) { console.error(`403 fetching domain — ${JSON.stringify(d.json)}`); }
  }

  // Read existing records so we don't create duplicates.
  const existing = await api("GET", `/v4/domains/${DOMAIN}/records`);
  if (!existing.ok) {
    console.error(`Could not read existing records (${existing.status}): ${JSON.stringify(existing.json)}`);
    if (existing.status === 403) {
      console.error("\nThis is the SAML block — the token isn't authorized for the team. Enter the records by hand in the dashboard instead.");
    }
    process.exit(1);
  }
  const have = (existing.json?.records || []);
  const norm = v => String(v).replace(/^["']|["']$/g, "").trim();
  const present = (r) => have.some(h =>
    h.type === r.type && (h.name === r.name || h.name === "") &&
    norm(h.value).startsWith(norm(r.value).slice(0, 24)));

  for (const r of RECORDS) {
    if (present(r)) { console.log(`= already present: ${r.type} ${r.name}`); continue; }
    const res = await api("POST", `/v2/domains/${DOMAIN}/records`, r);
    if (res.ok) console.log(`+ added: ${r.type} ${r.name}${r.mxPriority ? ` (prio ${r.mxPriority})` : ""}`);
    else {
      console.error(`x failed ${r.type} ${r.name} (${res.status}): ${JSON.stringify(res.json)}`);
      if (res.status === 403) { console.error("SAML block — do it by hand in the dashboard."); process.exit(1); }
    }
  }
  console.log("\nDone. Next: node scripts/resend-domain-setup.mjs verify");
})();
