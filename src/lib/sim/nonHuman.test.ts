// One "not a person" rule for the story re-homing and the named-organization swap (Sdema review K7).
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { isNonHumanAccount, isRehomeablePerson } from "./nonHuman";
import { COMPANY_ASSETS } from "./companyProfilesMeta";
import { ATTACK_STORIES, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { COMPANY_EVENTS } from "./companyProfiles";
import { tenantRoster, parseTenant, type Tenant } from "@/lib/team/tenant";

describe("non-human accounts", () => {
  it("service, role, decoy and device accounts are not people", () => {
    for (const a of ["it.admin@nexacorp.com", "it-admin@nexacorp.com", "admin@rocketstack.io", "svc-backup@nexacorp.com", "cyberark.svc@quantumbank.ch",
      "helpdesk@nexacorp.com", "servicedesk@quantumbank.ch", "soc.t2@nexacorp.com", "security-admin@quantumbank.ch", "sec-canary.finance@nexacorp.com",
      "dba@nexacorp.com", "trading-desk4@nexacorp.com", "wh-shift-a@globallogis.de", "finance-team@nexacorp.com", "mtr.boardroom3@nexacorp.com",
      "ci-pipeline@rocketstack.io", "svc_bkp_agent@nexacorp.com", "it.admin.gl@globallogis.de", "ops-admin@rocketstack.io"]) {
      expect(isNonHumanAccount(a), a).toBe(true);
    }
  });
  it("every person on a company roster is a person, a tiered admin account too", () => {
    const people = Object.values(COMPANY_ASSETS).flatMap(a => a.roster.filter(r => !/deploy/i.test(r.name)).map(r => `${r.name}@${a.domain}`));
    expect(people.filter(isNonHumanAccount)).toEqual([]);
    expect(isNonHumanAccount("admin.vandenberg@medcorehealth.org")).toBe(false);
  });
  it("an account without @ is never re-homed", () => {
    expect(isRehomeablePerson("assist-enduser-7731")).toBe(false);
    expect(isRehomeablePerson("d.cohen@nexacorp.com")).toBe(true);
  });
});

describe("story re-homing keeps non-people as they are", () => {
  const pool = COMPANY_EVENTS.nexacorp ?? [];
  it("the RAG chat's anonymous session user stays the chat user, never an employee", () => {
    const story = ATTACK_STORIES.find(s => s.id === "ai-rag-chatbot-document-injection")!;
    for (const seed of [0.01, 0.3, 0.6, 0.99]) {
      // The story names the chat end user (a session id, no "@") in the Defender for Cloud AI alert's
      // end-user context since the RAG story's XDR rework (eb9f8b68): it survives instantiation as written.
      const evs = instantiateStory(story, pool, "Microsoft Defender for Endpoint", "nexacorp", () => seed).events;
      const authored = JSON.stringify(story.events).match(/assist-enduser-\d+/)?.[0];
      expect(authored).toBeTruthy();
      expect(JSON.stringify(evs)).toContain(authored!);
    }
  });
  it("no story's victim is re-homed onto a non-human account, and a non-human account is never renamed to a person", () => {
    const wrong: string[] = [];
    for (const story of ATTACK_STORIES) {
      for (const seed of [0.2, 0.7]) {
        let evs;
        try { evs = instantiateStory(story, pool, "Microsoft Defender for Endpoint", "nexacorp", () => seed).events; } catch { continue; }
        story.events.forEach((a, i) => {
          const b = evs[i];
          if (!a.user_email || !b?.user_email || a.id !== b.id) return;
          if (isRehomeablePerson(a.user_email) && a.user_email !== b.user_email && isNonHumanAccount(b.user_email)) wrong.push(`${story.id}: ${a.user_email} -> ${b.user_email}`);
          if (isNonHumanAccount(a.user_email) && a.user_email.split("@")[0] !== b.user_email.split("@")[0]) wrong.push(`${story.id}: ${a.user_email} renamed ${b.user_email}`);
        });
      }
    }
    expect(wrong).toEqual([]);
  });
  it("the named organization keeps it.admin a generic account", () => {
    const t = parseTenant("sdemagroup") as Tenant;
    const r = tenantRoster([{ email: "it.admin@nexacorp.com" }, { email: "d.cohen@nexacorp.com", title: "HR Manager" }], t, "s1");
    expect(r.get("it.admin@nexacorp.com")?.email).toBe("it.admin@sdemagroup.com");
    expect(r.get("d.cohen@nexacorp.com")?.local).not.toBe("d.cohen");
  });
});
