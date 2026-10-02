// A team exercise run as the instructor's own organization: English-only name → domain,
// random people and roles, and not one trace of the template company left anywhere.
import { describe, it, expect } from "vitest";
import { parseTenant, tenantRoster, deptOf, tenantIdentity, TENANT_TEMPLATE, type Tenant } from "./tenant";
import { buildTeamTimeline } from "./buildTimeline";
import { teamLoad } from "./load";
import { nativeView } from "@/lib/logs/native";
import type { TelemetryEvent } from "@/lib/sim/types";

const roster5 = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];

describe("organization name → identity", () => {
  it("accepts English names and derives the domain", () => {
    const t = parseTenant("Acme-Labs") as Tenant;
    expect(t).toMatchObject({ domain: "acme-labs.com", slug: "acme-labs", brand: "AcmeLabs", netbios: "ACMELABS", code: "ACM" });
    expect((parseTenant("contoso.io") as Tenant).domain).toBe("contoso.io");
  });
  it("rejects non-English, empty, malformed and demo-company names", () => {
    for (const bad of ["", "אקמה", "acme corp", "a", "1acme", "acme_", "acme-", "acme--labs", "nexacorp", "medcorehealth.org"]) {
      expect("error" in parseTenant(bad), bad).toBe(true);
    }
  });
});

describe("random employees", () => {
  it("are stable per session, unique, and keep their department", () => {
    const t = parseTenant("acme") as Tenant;
    const users = [{ email: "a.jones@nexacorp.com", title: "Systems Admin" }, { email: "j.chen@nexacorp.com", title: "Financial Analyst" },
      { email: "s.patel@nexacorp.com", title: "HR Manager" }, { email: "svc-backup@nexacorp.com" }];
    const a = tenantRoster(users, t, "seed-1"), b = tenantRoster(users, t, "seed-1"), c = tenantRoster(users, t, "seed-2");
    expect([...a.values()]).toEqual([...b.values()]);
    expect([...a.values()].map(p => p.email)).not.toEqual([...c.values()].map(p => p.email));
    expect(new Set([...a.values()].map(p => p.email)).size).toBe(4);
    expect(deptOf(a.get("a.jones@nexacorp.com")!.title)).toBe("it");
    expect(deptOf(a.get("j.chen@nexacorp.com")!.title)).toBe("finance");
    expect(a.get("svc-backup@nexacorp.com")!.email).toBe("svc-backup@acme.com");   // a service account keeps its name
    for (const p of a.values()) expect(p.email.endsWith("@acme.com")).toBe(true);
  });
});

describe("the exercise rendered as the named organization", () => {
  const tenant = parseTenant("acme-labs") as Tenant;
  for (const diff of ["easy", "medium", "hard"] as const) {
    it(`${diff}: no trace of the template company; everyone is @${tenant.domain}`, () => {
      const tl = buildTeamTimeline(TENANT_TEMPLATE, diff, `tenant-${diff}`, null, teamLoad(diff, roster5), {}, tenant);
      const leak = /nexacorp|NEXACORP|NexaCorp|-NXC-|\bNXC-/;
      const problems: string[] = [];
      for (const e of tl) {
        const text = JSON.stringify([e.body, e.answer ?? {}]);
        const m = text.match(leak);
        if (m) problems.push(`${(e.body as { id?: string }).id}: "${m[0]}" — ${text.slice(Math.max(0, text.indexOf(m[0]) - 60), text.indexOf(m[0]) + 40)}`);
        const mails = text.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) ?? [];
        for (const mail of mails) if (mail.toLowerCase().endsWith("@nexacorp.com")) problems.push(`${mail} survived`);
      }
      expect(problems.slice(0, 10)).toEqual([]);
      // Native records carry the organization's domain (UPN / FQDN), never the template's.
      const feed = tl.filter(e => e.channel === "feed").map(e => e.body as unknown as TelemetryEvent);
      let native = 0;
      for (const ev of feed.slice(0, 300)) {
        const v = nativeView(ev, TENANT_TEMPLATE, {}, tenantIdentity(tenant));
        if (!v) continue;
        native++;
        const t = JSON.stringify(v.log.record) + (v.log.rawLine ?? "");
        expect(t, `${ev.id} ${v.log.sourceId}`).not.toMatch(leak);
      }
      expect(native).toBeGreaterThan(50);
    });
  }
});
