// The background story holds together (Tal's QA of the SOC Dashboard, 2026-11-12, section 3): a person keeps one
// job and one desk, a company's ordinary sign-ins come from where the company is, nothing in a log is a leftover
// template, a row never dates itself relative to a time the feed does not show, and the internet reaches an
// internal address only through a publish rule (NAT). Other companies' host names in a company's rows are the
// technical-integrity gate's rule 3b.
import { describe, expect, it } from "vitest";
import { ATTACK_STORIES, canonicalTitles, instantiateStory, storiesForCompany } from "@/app/(app)/dashboard/attackStories";
import { companyFeedPool, feedCompanyProfile } from "@/app/(app)/dashboard/feedPool";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { COMPANY_ASSETS, COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import type { TelemetryEvent } from "@/lib/sim/types";

const COMPANIES = COMPANY_PROFILES.map(c => c.id);
const pool = (c: string) => companyFeedPool({ BENIGN_EVENTS, COMPANY_EVENTS }, c);
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
const WORKSTATION = /^(lap|ws|wks|lt|nb|desktop|laptop|macbook|mbp)([-_]|\d)/i;
const strings = (v: unknown, out: string[] = []): string[] => {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) v.forEach(x => strings(x, out));
  else if (v && typeof v === "object") Object.values(v).forEach(x => strings(x, out));
  return out;
};
const allRows = (): { e: TelemetryEvent; where: string }[] => [
  ...ATTACK_STORIES.flatMap(s => s.events.map(e => ({ e, where: s.id }))),
  ...BENIGN_EVENTS.map(e => ({ e, where: "benign" })),
  ...Object.entries(COMPANY_EVENTS).flatMap(([c, evs]) => evs.map(e => ({ e, where: c }))),
];
const fixedRnd = () => { let k = 0.37; return () => (k = (k * 9301 + 0.49297) % 1); };

describe("one person, one job, one desk", () => {
  for (const c of COMPANIES) {
    it(`${c}: a person's rows carry one title, the roster's`, () => {
      const titles = new Map<string, Set<string>>();
      for (const e of pool(c)) if (e.user_email && e.user_title) titles.set(e.user_email, new Set([...(titles.get(e.user_email) ?? []), e.user_title]));
      const roster = new Map(COMPANY_ASSETS[c].roster.map(r => [`${r.name}@${COMPANY_ASSETS[c].domain}`, r.title]));
      const bad: string[] = [];
      for (const [u, t] of titles) {
        if (t.size > 1) bad.push(`${u}: ${[...t].join(" | ")}`);
        const r = roster.get(u);
        if (r && !t.has(r)) bad.push(`${u}: rows say ${[...t].join(" | ")}, roster says ${r}`);
      }
      expect(bad).toEqual([]);
    });

    it(`${c}: a story's rows give a company person the title they have everywhere else`, () => {
      const canon = canonicalTitles(pool(c), COMPANY_ASSETS[c]);
      const bad: string[] = [];
      for (const s of storiesForCompany(c)) {
        const out = instantiateStory(s, pool(c), feedCompanyProfile(c).architecture?.edr, c, fixedRnd());
        for (const e of out.events) {
          const t = e.user_email ? canon.get(e.user_email.toLowerCase()) : undefined;
          if (t && e.user_title && e.user_title !== t) bad.push(`${s.id} ${e.id}: ${e.user_email} as ${e.user_title}, elsewhere ${t}`);
        }
      }
      expect(bad.slice(0, 10)).toEqual([]);
    });

    it(`${c}: a story drawn onto a person sits at that person's own desk`, () => {
      // The desk a person's own rows name most in the company feed.
      const counts = new Map<string, Map<string, number>>();
      for (const e of pool(c)) if (e.user_email && e.hostname && WORKSTATION.test(e.hostname)) {
        const m = counts.get(e.user_email) ?? new Map<string, number>(); m.set(e.hostname, (m.get(e.hostname) ?? 0) + 1); counts.set(e.user_email, m);
      }
      const primary = (u: string) => { const m = counts.get(u); return m ? [...m.entries()].sort((a, b) => b[1] - a[1])[0][0] : undefined; };
      const bad: string[] = [];
      for (const s of storiesForCompany(c)) {
        if (s.seat) continue;   // a seat story brings its own person and machine
        // The authored victim worked at exactly one workstation: the drawn person must too, at their own.
        const authoredDesks = new Set(s.events.filter(e => e.user_email && e.hostname && WORKSTATION.test(e.hostname)).map(e => `${e.user_email}|${e.hostname}`));
        const byUser = new Map<string, Set<string>>();
        for (const k of authoredDesks) { const [u, h] = k.split("|"); byUser.set(u, new Set([...(byUser.get(u) ?? []), h])); }
        if (![...byUser.values()].every(v => v.size === 1)) continue;
        const out = instantiateStory(s, pool(c), feedCompanyProfile(c).architecture?.edr, c, fixedRnd());
        const seen = new Map<string, Set<string>>();
        for (const e of out.events) if (e.user_email && e.hostname && WORKSTATION.test(e.hostname)) seen.set(e.user_email, new Set([...(seen.get(e.user_email) ?? []), e.hostname]));
        for (const [u, hs] of seen) {
          const p = primary(u);
          if (p && hs.size === 1 && !hs.has(p) && ![...counts.values()].some(m => m.has([...hs][0]) && (m.get([...hs][0]) ?? 0) > (counts.get(u)?.get(p) ?? 0)))
            bad.push(`${s.id}: ${u} at ${[...hs][0]}, their desk is ${p}`);
        }
      }
      expect(bad.slice(0, 10)).toEqual([]);
    });
  }
});

describe("a company is where its office is", () => {
  for (const c of COMPANIES) it(`${c}: ordinary sign-ins come from the office country, and "usual" names it`, () => {
    const office = COMPANY_ASSETS[c].office?.country;
    const bad: string[] = [];
    for (const e of pool(c)) {
      const m = (e.description ?? "").match(/usual \(([^)]+)\)/);
      if (m && m[1] !== office) bad.push(`${e.id}: usual ${m[1]}, office ${office}`);
      const ordinary = !e.expected_verdict && !e.mitre_technique && !e.is_detection && /auth_success|vpn_login/.test(e.event_type);
      if (ordinary && office && e.geo?.country && e.geo.country !== office) bad.push(`${e.id}: ${e.geo.country}, office ${office}`);
    }
    expect(bad).toEqual([]);
  });
});

describe("nothing in a log is a leftover", () => {
  it("no template placeholder ({{Name}}) in any field, decoded PowerShell included", () => {
    const bad: string[] = [];
    for (const { e, where } of allRows()) {
      for (const s of strings(e)) {
        if (/\{\{\s*[A-Za-z_][\w-]*\s*\}\}/.test(s)) bad.push(`${where} ${e.id}: ${s.slice(0, 60)}`);
        for (const m of s.matchAll(/-(?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})/gi)) {
          const decoded = Buffer.from(m[1], "base64").toString("utf16le");
          if (/\{\{|\}\}/.test(decoded)) bad.push(`${where} ${e.id} decodes to ${decoded.slice(0, 60)}`);
        }
      }
    }
    expect(bad).toEqual([]);
  });

  it("a row that happens now never dates itself in the past (yesterday, three days earlier)", () => {
    // The feed re-times every row of a pool and every row of a story to the shift's clock.
    const bad = allRows().filter(({ e }) => (e.is_baseline || !e.mitre_technique) && /\b(yesterday|last week|(?:days|hours|weeks) earlier)\b/i.test(e.description ?? ""))
      .map(({ e, where }) => `${where} ${e.id}: ${e.description!.slice(0, 80)}`);
    expect(bad).toEqual([]);
  });
});

describe("the internet reaches an internal address only through NAT", () => {
  it("an inbound session from a public address names the public address, or the server as its translation", () => {
    const bad = allRows().filter(({ e }) => ["firewall", "ids", "waf"].includes(e.source) && !!e.src_ip && !PRIVATE.test(e.src_ip) && !!e.dst_ip && PRIVATE.test(e.dst_ip)
      && !(e.raw?.["pan.natdst"] && e.raw?.["pan.dst"]))
      .map(({ e, where }) => `${where} ${e.id}: ${e.src_ip} -> ${e.dst_ip}`);
    expect(bad).toEqual([]);
  });
});

describe("one name per file server", () => {
  // QA 2026-11-13: a story that named its file server only inside text (FS-ENG-01 in a description, FS-PROD-03 as a
  // VM's inventory name) kept that name on every company. A rendered story names the company's own file server.
  const FILE_SERVER = /\b(?:SRV-[A-Z0-9-]*(?:FILE|FILES|FS)\d*[A-Z0-9-]*|FS-[A-Z]+-\d{2,3})\b/g;
  for (const c of COMPANIES) {
    it(`${c}: every file server a story names is the company's own`, () => {
      const own = COMPANY_ASSETS[c]?.fileServer;
      const bad = new Set<string>();
      const seen = new Set<string>();
      for (const d of ["easy", "medium", "hard"] as const) for (const base of [...storiesForCompany(c, d), ...storiesForCompany(c, d, "team")]) {
        if (seen.has(base.id)) continue;
        seen.add(base.id);
        const out = instantiateStory(base, pool(c), feedCompanyProfile(c).architecture?.edr, c, fixedRnd());
        for (const s of strings(out.events)) for (const m of s.matchAll(FILE_SERVER)) {
          const name = m[0];
          if (/ADFS/i.test(name) || name === own || name.startsWith(`${own}-`)) continue;
          bad.add(`${base.id}: ${name}`);
        }
      }
      expect([...bad].slice(0, 10)).toEqual([]);
    }, 300_000);
  }
});
