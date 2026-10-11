/**
 * Resend domain setup driver — does the whole Resend side of enabling email to
 * ANY recipient (not just the account owner), via the Resend API, so it needs
 * no Resend dashboard clicks.
 *
 * It reads RESEND_API_KEY from the environment or from .env.local (same file
 * DATABASE_URL already lives in), so the secret never has to be pasted into a
 * chat or committed anywhere.
 *
 * Usage:
 *   node scripts/resend-domain-setup.mjs add        # add hackthesoc.app, print DNS records to paste into Vercel
 *   node scripts/resend-domain-setup.mjs records     # re-print the records for the existing domain
 *   node scripts/resend-domain-setup.mjs verify      # ask Resend to re-check DNS and report status
 *
 * After `add`: paste the printed records into Vercel DNS, then run `verify`
 * until status is "verified". Then set EMAIL_FROM in Vercel and redeploy.
 */
import fs from "node:fs";
import path from "node:path";

const DOMAIN = "hackthesoc.app";
const API = "https://api.resend.com";

// --- load RESEND_API_KEY (env first, then .env.local) ---------------------
function loadKey() {
  if (process.env.RESEND_API_KEY?.trim()) return process.env.RESEND_API_KEY.trim();
  const envPath = path.join(process.cwd(), ".env.local");
  if (fs.existsSync(envPath)) {
    for (const line of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
      const m = line.match(/^\s*RESEND_API_KEY\s*=\s*(.+?)\s*$/);
      if (m) return m[1].replace(/^["']|["']$/g, "").trim();
    }
  }
  return null;
}

const KEY = loadKey();
if (!KEY) {
  console.error(
    "RESEND_API_KEY not found.\n" +
    "Add it to .env.local (the same file DATABASE_URL is in):\n" +
    "  RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxx\n" +
    "You can copy the key from Resend → API Keys (or reuse the one already in Vercel)."
  );
  process.exit(1);
}

async function api(method, pathname, body) {
  const res = await fetch(API + pathname, {
    method,
    headers: { Authorization: `Bearer ${KEY}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json;
  try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  if (!res.ok) {
    throw new Error(`${method} ${pathname} → ${res.status}: ${JSON.stringify(json)}`);
  }
  return json;
}

async function findDomain() {
  const list = await api("GET", "/domains");
  const items = Array.isArray(list?.data) ? list.data : Array.isArray(list) ? list : [];
  return items.find(d => d.name === DOMAIN) || null;
}

function printRecords(domain) {
  const recs = domain.records || [];
  console.log(`\nDomain: ${domain.name}  |  region: ${domain.region}  |  status: ${domain.status}\n`);
  console.log("Add EACH of these in Vercel → Domains → hackthesoc.app → DNS Records → Add.");
  console.log("Vercel appends the domain automatically, so enter the NAME exactly as shown");
  console.log("(e.g. 'send', 'resend._domainkey') — NOT the full '...hackthesoc.app'.\n");
  for (const [i, r] of recs.entries()) {
    console.log(`--- record ${i + 1} ---`);
    console.log(`  Type:     ${r.type}`);
    console.log(`  Name:     ${r.name}`);
    if (r.priority !== undefined && r.priority !== null) console.log(`  Priority: ${r.priority}`);
    console.log(`  Value:    ${r.value}`);
    if (r.ttl) console.log(`  TTL:      ${r.ttl}`);
    console.log(`  (Resend status for this record: ${r.status})`);
    console.log("");
  }
}

const action = (process.argv[2] || "records").toLowerCase();

try {
  if (action === "add") {
    let domain = await findDomain();
    if (domain) {
      console.log("Domain already exists in Resend — printing its records instead of re-adding.");
    } else {
      // us-east-1 is Resend's default region; keep it unless the account is EU-pinned.
      domain = await api("POST", "/domains", { name: DOMAIN, region: "us-east-1" });
      console.log("Domain added to Resend.");
    }
    // re-fetch full record set by id for freshest values
    const full = await api("GET", `/domains/${domain.id}`);
    printRecords(full);
  } else if (action === "records") {
    const d = await findDomain();
    if (!d) { console.error(`${DOMAIN} is not in Resend yet — run: node scripts/resend-domain-setup.mjs add`); process.exit(1); }
    const full = await api("GET", `/domains/${d.id}`);
    printRecords(full);
  } else if (action === "verify") {
    const d = await findDomain();
    if (!d) { console.error(`${DOMAIN} is not in Resend yet — run: node scripts/resend-domain-setup.mjs add`); process.exit(1); }
    await api("POST", `/domains/${d.id}/verify`);
    const full = await api("GET", `/domains/${d.id}`);
    console.log(`\nStatus: ${full.status}`);
    const pending = (full.records || []).filter(r => r.status && r.status !== "verified");
    if (full.status === "verified") {
      console.log("✅ Verified — you can now send to any recipient once EMAIL_FROM points at this domain.");
    } else {
      console.log(`Still pending. ${pending.length} record(s) not yet verified (DNS can take minutes–hours):`);
      for (const r of pending) console.log(`  - ${r.type} ${r.name} → ${r.status}`);
    }
  } else {
    console.error(`Unknown action "${action}". Use: add | records | verify`);
    process.exit(1);
  }
} catch (e) {
  console.error("Resend API error:", e.message);
  process.exit(1);
}
