/**
 * A team exercise runs as the organization the instructor names — not as one of the
 * Live-SOC demo companies. The instructor types the organization's English name (it is
 * the domain: "acme" → acme.com, or "acme.io" as typed); the session draws its own
 * random employees and roles, and every log, the story, the attack surface and the
 * answer key are rendered under that identity.
 *
 * Under the hood the exercise is built on a template environment (its noise pool, asset
 * registry and architecture — TENANT_TEMPLATE); applyTenant() then replaces every
 * identity the template carries: its people (email, username, display name, title), its
 * domain / realm / SharePoint tenant / brand / host-name code, and a look-alike domain
 * built on its name (nexacorp-portal.ru → acme-portal.ru), in the public feed, the
 * answer key and the inject texts alike. Native renderers get the tenant's domain and
 * realm through tenantIdentity().
 */
import { COMPANY_ASSETS, COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import type { TimelineEntry } from "./buildTimeline";

/** The environment a named-organization exercise is built on (Live SOC companies are untouched). */
export const TENANT_TEMPLATE = "nexacorp";

export interface Tenant {
  /** As typed, trimmed ("Acme-Labs"). */
  name: string;
  /** DNS / mail domain (acme-labs.com, or the domain as typed). */
  domain: string;
  /** Lower-case label the domain starts with (acme-labs) — SharePoint tenant, look-alike domains. */
  slug: string;
  /** Brand as it appears in prose ("AcmeLabs"). */
  brand: string;
  /** NetBIOS realm (ACMELABS, ≤ 15). */
  netbios: string;
  /** Three-letter host-name code (ACM → SRV-ACM-DC01). */
  code: string;
}

const NAME_RE = /^[a-z][a-z0-9-]{1,29}(\.[a-z]{2,12}){0,2}$/i;

/** The organization name → its identity, or a reason it can't be used. English only. */
export function parseTenant(input: unknown): Tenant | { error: string } {
  const raw = typeof input === "string" ? input.trim() : "";
  if (!raw) return { error: "Enter the organization's name in English." };
  if (/[^\x20-\x7e]/.test(raw)) return { error: "Use English letters only (a-z), digits and hyphens." };
  if (!NAME_RE.test(raw) || /--|-\.|\.-|-$/.test(raw)) return { error: "2–30 characters: English letters, digits and hyphens, starting with a letter (e.g. acme or acme-labs.io)." };
  const lower = raw.toLowerCase();
  const slug = lower.split(".")[0];
  const domain = lower.includes(".") ? lower : `${slug}.com`;
  const words = slug.split("-").filter(Boolean);
  const brand = words.map(w => w.charAt(0).toUpperCase() + w.slice(1)).join("");
  const netbios = slug.replace(/-/g, "").toUpperCase().slice(0, 15);
  const reserved = Object.values(COMPANY_ASSETS).flatMap(a => [a.domain, a.domain.split(".")[0]]);
  if (reserved.includes(domain) || reserved.includes(slug)) return { error: "That name belongs to a Live-SOC demo company — use your organization's own name." };
  return { name: raw, domain, slug, brand, netbios, code: netbios.replace(/[^A-Z]/g, "").padEnd(3, "X").slice(0, 3) };
}

/** The session's organization from team_sessions.config (re-validated — never trusted as stored). */
export function tenantFromConfig(config: unknown): Tenant | null {
  const name = (config as { tenant?: { name?: unknown } } | null)?.tenant?.name;
  if (typeof name !== "string") return null;
  const t = parseTenant(name);
  return "error" in t ? null : t;
}

/** Domain + realm for the native renderers (makeCtx overrides). */
export function tenantIdentity(t: Tenant | null | undefined): { domain: string; netbios: string } | undefined {
  return t ? { domain: t.domain, netbios: t.netbios } : undefined;
}

// ── random employees ────────────────────────────────────────────────────────────
const FIRST = ["Adam", "Alice", "Amir", "Anna", "Ben", "Carla", "Chen", "Daniel", "Dana", "David", "Elena", "Eli", "Emma", "Erik", "Farah",
  "Gal", "George", "Hana", "Ian", "Ines", "Isaac", "Jana", "Jonas", "Julia", "Karim", "Kate", "Leo", "Lina", "Lucas", "Maya", "Marco",
  "Mia", "Nadia", "Noah", "Nora", "Omar", "Olivia", "Paul", "Priya", "Rafael", "Rina", "Ruth", "Sam", "Sara", "Simon", "Sofia", "Tal",
  "Tom", "Uma", "Victor", "Wen", "Yael", "Yusuf", "Zoe"];
const LAST = ["Abrams", "Ahmed", "Alvarez", "Bauer", "Bennett", "Bianchi", "Cohen", "Costa", "Dahl", "Dubois", "Evans", "Fischer", "Garcia",
  "Haddad", "Hansen", "Ito", "Jensen", "Kaplan", "Khan", "Klein", "Kowalski", "Larsen", "Levi", "Lopez", "Mendes", "Meyer", "Moreau",
  "Nakamura", "Novak", "Okafor", "Olsen", "Peretz", "Petrov", "Quinn", "Rossi", "Sato", "Schmidt", "Shapiro", "Silva", "Stein", "Tanaka",
  "Torres", "Vogel", "Walsh", "Weiss", "Yilmaz", "Zimmer"];
export type Dept = "it" | "eng" | "finance" | "hr" | "legal" | "sales" | "exec" | "ops" | "general";
const TITLES: Record<Dept, string[]> = {
  it: ["Systems Administrator", "IT Administrator", "Network Engineer", "Infrastructure Engineer", "Cloud Engineer", "IT Support Specialist"],
  eng: ["Software Engineer", "Senior Developer", "DevOps Engineer", "Backend Developer", "QA Engineer", "Data Engineer"],
  finance: ["Financial Analyst", "Accountant", "Finance Manager", "Payroll Specialist", "Risk Analyst", "Treasury Analyst"],
  hr: ["HR Manager", "HR Business Partner", "Recruiter", "People Operations Specialist"],
  legal: ["Legal Counsel", "Compliance Officer", "Contracts Manager"],
  sales: ["Account Executive", "Sales Manager", "Business Development Rep", "Customer Success Manager"],
  exec: ["Chief Financial Officer", "VP Operations", "Director of Finance", "Chief Operating Officer"],
  ops: ["Operations Manager", "Office Manager", "Procurement Specialist", "Facilities Coordinator"],
  general: ["Project Manager", "Business Analyst", "Product Manager", "Executive Assistant", "Marketing Specialist"],
};
/** The department a template title belongs to — a finance user stays in finance, an admin stays IT. */
export function deptOf(title?: string): Dept {
  const t = (title ?? "").toLowerCase();
  if (/chief|\bvp\b|director|head of|ceo|cfo|coo|cto/.test(t)) return "exec";
  if (/admin|sysadmin|infrastructure|network|\bit\b|helpdesk|support|security|cloud/.test(t)) return "it";
  if (/devops|developer|software|engineer|qa\b|data/.test(t)) return "eng";
  if (/financ|account|payroll|treasur|risk|trad|controller|audit/.test(t)) return "finance";
  if (/\bhr\b|people|recruit|talent/.test(t)) return "hr";
  if (/legal|counsel|compliance|contract/.test(t)) return "legal";
  if (/sales|account exec|business dev|customer/.test(t)) return "sales";
  if (/operation|office|procure|facilit|logistic/.test(t)) return "ops";
  return "general";
}

function hash32(s: string): number { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
function rng(seed: string) { let x = hash32(seed) || 1; return () => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return (x >>> 0) / 4294967296; }; }

// Accounts that are not people keep their (generic) name — only their domain changes.
const NON_HUMAN = /^(svc[-._]|ci-|noreply|system|admin@|it\.admin|helpdesk|dba|soc|security|backup|scanner|printer|device|kiosk)|(^|[-._])(service|svc|replication|deploy|monitor|daemon|automation|bot|sync|scan|sql|dc)([-._@]|$)/i;

export interface TenantPerson { email: string; local: string; name: string; title: string }

/**
 * A stable random person for every template identity the timeline mentions: same first-name
 * pool / surname pool, unique per session, title drawn from the same department.
 */
export function tenantRoster(templateUsers: { email: string; title?: string }[], tenant: Tenant, seed: string): Map<string, TenantPerson> {
  const r = rng(`${seed}:${tenant.domain}:roster`);
  const out = new Map<string, TenantPerson>();
  const usedLocal = new Set<string>(), usedName = new Set<string>();
  for (const u of [...templateUsers].sort((a, b) => a.email.localeCompare(b.email))) {
    if (out.has(u.email)) continue;
    const local0 = u.email.split("@")[0];
    if (NON_HUMAN.test(local0) || NON_HUMAN.test(u.email)) {
      out.set(u.email, { email: `${local0}@${tenant.domain}`, local: local0, name: local0, title: u.title ?? "" });
      continue;
    }
    let first = "", last = "", local = "";
    for (let tries = 0; tries < 200; tries++) {
      first = FIRST[Math.floor(r() * FIRST.length)]; last = LAST[Math.floor(r() * LAST.length)];
      local = `${first.charAt(0).toLowerCase()}.${last.toLowerCase()}`;
      if (!usedLocal.has(local) && !usedName.has(`${first} ${last}`)) break;
    }
    if (usedLocal.has(local)) local = `${local}${usedLocal.size}`;
    usedLocal.add(local); usedName.add(`${first} ${last}`);
    const titles = TITLES[deptOf(u.title)];
    out.set(u.email, { email: `${local}@${tenant.domain}`, local, name: `${first} ${last}`, title: u.title ? titles[Math.floor(r() * titles.length)] : "" });
  }
  return out;
}

function mapStrings(value: unknown, f: (s: string) => string): unknown {
  if (typeof value === "string") return f(value);
  if (Array.isArray(value)) return value.map(v => mapStrings(v, f));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, mapStrings(v, f)]));
  return value;
}

function deepReplace(value: unknown, pairs: [string, string][]): unknown {
  if (typeof value === "string") {
    let s = value;
    for (const [f, t] of pairs) if (f && s.includes(f)) s = s.split(f).join(t);
    return s;
  }
  if (Array.isArray(value)) return value.map(v => deepReplace(v, pairs));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, deepReplace(v, pairs)]));
  return value;
}

/**
 * The timeline as the named organization's: people, titles, domain, realm, SharePoint
 * tenant, brand, host-name code — feed bodies, answer keys and inject texts alike.
 */
export function applyTenant(entries: TimelineEntry[], templateId: string, tenant: Tenant, seed: string): TimelineEntry[] {
  const tpl = COMPANY_ASSETS[templateId];
  const tplBrand = (COMPANY_PROFILES.find(c => c.id === templateId)?.name ?? templateId).split(/\s+/)[0];
  const tplDomain = tpl?.domain ?? `${templateId}.com`;
  const tplStem = tplDomain.split(".")[0];
  const tplNetbios = tpl?.netbios ?? templateId.toUpperCase();
  const tplCode = (() => {   // the template's host-name code: SRV-NXC-DC01 → NXC
    const counts = new Map<string, number>();
    for (const e of entries) {
      const h = (e.body as { hostname?: unknown }).hostname;
      const m = typeof h === "string" ? /^(?:SRV|SVR)-([A-Z]{2,5})-/.exec(h) : null;
      if (m) counts.set(m[1], (counts.get(m[1]) ?? 0) + 1);
    }
    return [...counts].sort((a, b) => b[1] - a[1])[0]?.[0];
  })();

  // Every template person the timeline mentions (mail address at the template's domain), with a title if any log shows one.
  const titles = new Map<string, string>();
  const emails = new Set<string>();
  const mailRe = new RegExp(`[a-z0-9._%+-]+@${tplDomain.replace(/\./g, "\\.")}`, "gi");
  for (const e of entries) {
    const b = e.body as { user_email?: unknown; user_title?: unknown; user?: { email?: unknown; title?: unknown } };
    for (const m of JSON.stringify([e.body, e.answer ?? {}]).match(mailRe) ?? []) emails.add(m.toLowerCase());
    const em = typeof b.user_email === "string" ? b.user_email.toLowerCase() : undefined;
    const ti = typeof b.user_title === "string" ? b.user_title : typeof b.user?.title === "string" ? b.user.title : undefined;
    if (em && ti && !titles.has(em)) titles.set(em, ti);
  }
  const roster = tenantRoster([...emails].map(email => ({ email, title: titles.get(email) })), tenant, seed);

  const pairs: [string, string][] = [];
  const firstNames: [string, string][] = [];
  const allText = JSON.stringify(entries.map(e => [e.body, e.answer ?? {}]));
  for (const [oldEmail, p] of roster) {
    const oldLocal = oldEmail.split("@")[0];
    pairs.push([oldEmail, p.email]);
    if (p.local === oldLocal) continue;   // a non-human account keeps its name
    pairs.push([oldLocal, p.local]);
    if (oldLocal.includes(".")) pairs.push([oldLocal.replace(/\./g, ""), p.local.replace(/\./g, "")]);
    // Display names / first names of this person ("Jennifer Chen", "Jennifer uses …").
    const surname = oldLocal.split(/[._]/).pop() ?? "";
    if (/^[a-z'-]{3,}$/i.test(surname)) {
      const re = new RegExp(`\\b([A-Z][a-z]{2,}) (${surname.charAt(0).toUpperCase()}${surname.slice(1)})\\b`, "g");
      const pf = p.name.split(" ")[0];
      for (const m of new Set(allText.match(re) ?? [])) {
        const first = m.split(" ")[0];
        pairs.push([m, p.name]);
        if (first.length >= 3) firstNames.push([first, pf]);   // "Jennifer uses …" — whole word only
      }
    }
    const oldTitle = titles.get(oldEmail);
    if (oldTitle && p.title && oldTitle !== p.title) pairs.push([`"${oldTitle}"`, `"${p.title}"`]);
  }
  pairs.push(
    [tplDomain, tenant.domain],
    [`${tplStem}.sharepoint.com`, `${tenant.slug}.sharepoint.com`],
    [`${tplStem}-my.sharepoint.com`, `${tenant.slug}-my.sharepoint.com`],
    [`${tplStem}.onmicrosoft.com`, `${tenant.slug}.onmicrosoft.com`],
    [tplBrand, tenant.brand],
    [tplBrand.toUpperCase(), tenant.netbios],
    [tplBrand.charAt(0) + tplBrand.slice(1).toLowerCase(), tenant.brand],
    [tplStem, tenant.slug],
    [tplNetbios, tenant.netbios],
  );
  if (tplCode) {
    pairs.push([`-${tplCode}-`, `-${tenant.code}-`], [`-${tplCode.toLowerCase()}-`, `-${tenant.code.toLowerCase()}-`]);   // srv-nxc-dc01 (MDE DeviceName)
    firstNames.push([`${tplCode}`, tenant.code]);   // a bare code (ticket NXC-2041) — whole word only
  }
  const clean = pairs.filter(([f, t]) => f && f !== t).sort((a, b) => b[0].length - a[0].length);
  const words = firstNames.filter(([f, t]) => f !== t).map(([f, t]) => [new RegExp(`(?<![A-Za-z])${f}(?![A-Za-z])`, "g"), t] as const);
  const swap = (v: unknown): unknown => {
    let out = deepReplace(v, clean);
    if (words.length) out = mapStrings(out, s => words.reduce((acc, [re, t]) => acc.replace(re, t), s));
    return out;
  };
  return entries.map(e => ({ ...e, body: swap(e.body) as Record<string, unknown>, ...(e.answer ? { answer: swap(e.answer) as Record<string, unknown> } : {}) }));
}
