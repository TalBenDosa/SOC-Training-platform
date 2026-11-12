// The core attack catalog through the real Team-SOC pipeline: every story pickable for its companies
// and for a named organization, every step present in order, raw records complete, no placeholder
// junk, answer data absent from public rows, a benign look-alike in each story, and Team Training only.
import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import type { TelemetryEvent } from "@/lib/sim/types";
import { CORE_STORIES } from "@/app/(app)/dashboard/core-stories";
import { ATTACK_STORIES, instantiateStory, pickStoryForCompany, storiesForCompany } from "@/app/(app)/dashboard/attackStories";
import { companyFeedPool, feedCompanyProfile } from "@/app/(app)/dashboard/feedPool";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { nativeView } from "@/lib/logs/native";
import { buildTeamTimeline, classifyStoryEvent, teamStoryFilter, teamStoryPool, TEAM_ANSWER_FIELDS, type TimelineEntry } from "./buildTimeline";
import { TENANT_TEMPLATE } from "./tenant";
import { DEFAULT_ENV, PLATFORM_CHOICES, type TeamEnv } from "./environment";
import { storyCategory } from "./storyCategory";

const DIFFS = ["easy", "medium", "hard"] as const;
const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];
const FULL_ENV: TeamEnv = { platforms: PLATFORM_CHOICES.map(p => p.id), industry: "general" };
const JUNK = /\bundefined\b|\bNaN\b|\[object Object\]/;
const REAL_EMPTY = new Set(["azure.signinlogs.resultDescription", "azure.signinlogs.properties.deviceDetail.deviceId"]);
const emptyValues = (o: unknown, path = ""): string[] => {
  if (o === "") return [path];
  if (Array.isArray(o)) return o.flatMap((v, i) => emptyValues(v, `${path}[${i}]`));
  if (o && typeof o === "object") return Object.entries(o).flatMap(([k, v]) => emptyValues(v, path ? `${path}.${k}` : k));
  return [];
};
const offered = (company: string, id: string) => DIFFS.filter(d => teamStoryPool(company, d, null).filter(teamStoryFilter(company)).some(s => s.id === id));
type Body = TelemetryEvent & { raw: Record<string, unknown> };
/** A single-player story's rows as the dashboard renders them, by authored id. */
const soloRows = (id: string, company: string): Map<string, Body> => {
  const s = ATTACK_STORIES.find(x => x.id === id)!;
  const pool = companyFeedPool({ BENIGN_EVENTS, COMPANY_EVENTS }, company);
  return new Map(instantiateStory(s, pool, feedCompanyProfile(company).architecture?.edr, company, () => 0.5).events.map(e => [e.id, e as Body] as const));
};
/** One story's rows as a player receives them, by authored id. */
const rows = (id: string, company: string, seed = "rework"): Map<string, Body> => {
  const s = ATTACK_STORIES.find(x => x.id === id)!;
  const ids = new Set(s.events.map(e => e.id));
  const tl: TimelineEntry[] = buildTeamTimeline(company, offered(company, id)[0], seed, id);
  return new Map(tl.flatMap(e => {
    const orig = String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").replace(/__\d+$/, "");
    return ids.has(orig) ? [[orig, e.body as unknown as Body] as const] : [];
  }));
};
const nativeOf = (b: Body, company: string) => nativeView(b, company, {})?.log.record as Record<string, unknown> | undefined;
const props = (rec: Record<string, unknown> | undefined) => (rec?.properties ?? rec) as Record<string, unknown>;

describe("core attack catalog in the Team-SOC pipeline", () => {
  it("has at least ten stories, across every level", () => {
    expect(CORE_STORIES.length).toBeGreaterThanOrEqual(10);
    expect(new Set(CORE_STORIES.map(s => s.complexity))).toEqual(new Set(["foundation", "core", "advanced"]));
  });

  for (const s of CORE_STORIES) {
    describe(s.id, () => {
      const companies = COMPANIES.filter(c => offered(c, s.id).length > 0);

      it("has a real category and is Team Training only", () => {
        expect(storyCategory(s.id)).not.toBe("other");
        expect(ATTACK_STORIES.find(x => x.id === s.id)?.teamOnly).toBe(true);
      });

      it("is in the team pool of a built-in company", () => {
        expect(companies.length).toBeGreaterThan(0);
        for (const c of companies) expect(DIFFS.some(d => storiesForCompany(c, d).some(x => x.id === s.id))).toBe(true);
      });

      it("is pickable for a named organization running every platform", () => {
        const fits = teamStoryFilter(TENANT_TEMPLATE, {}, FULL_ENV);
        expect(DIFFS.some(d => teamStoryPool(TENANT_TEMPLATE, d, FULL_ENV).filter(fits).some(x => x.id === s.id))).toBe(true);
      });

      it("has a benign look-alike and attack rows", () => {
        const verdicts = s.events.map(classifyStoryEvent);
        expect(verdicts.some(v => v === "fp" || v === "benign")).toBe(true);
        expect(verdicts.filter(v => v === "tp" || v === "escalate").length).toBeGreaterThan(3);
      });

      it("uses English without long dashes", () => {
        for (const e of s.events) expect(`${e.description}${s.title}`).not.toMatch(/[–—]/);
      });

      for (const c of companies) {
        const d = offered(c, s.id)[0];
        it(`injects complete, ordered, rendered logs (${c}, ${d})`, () => {
          const tl = buildTeamTimeline(c, d, `core-${s.id}`, s.id);
          const ids = new Set(s.events.map(e => e.id));
          const story = tl.filter(e => ids.has(String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").replace(/__\d+$/, "")));
          expect(story.length).toBe(s.events.length);
          const offs = story.map(e => e.due_offset_ms);
          expect([...offs].sort((a, b) => a - b)).toEqual(offs);
          for (const e of story) {
            const raw = (e.body as { raw?: unknown }).raw;
            expect(raw, "every injected log carries its raw record").toBeTruthy();
            const txt = JSON.stringify(e.body);
            expect(JUNK.test(txt), `placeholder junk in ${txt.slice(0, 160)}`).toBe(false);
            expect(emptyValues(raw).filter(p => !REAL_EMPTY.has(p)), "raw fields with empty values").toEqual([]);
            for (const f of TEAM_ANSWER_FIELDS) expect(Object.keys(e.body), `answer field ${f} on a public row`).not.toContain(f);
          }
          expect(story.some(e => ["fp", "benign"].includes(String((e.answer as { expected_verdict?: string }).expected_verdict)))).toBe(true);
        });
      }
    });
  }

  it("is never returned by pickStoryForCompany", () => {
    const ids = new Set(CORE_STORIES.map(s => s.id));
    for (const c of COMPANIES) for (const d of DIFFS) {
      // The dashboard's whole candidate list, then the picker itself.
      expect(storiesForCompany(c, d, true).filter(s => ids.has(s.id)).map(s => s.id)).toEqual([]);
      for (let i = 0; i < 12; i++) expect(ids.has(pickStoryForCompany(c, d).id)).toBe(false);
    }
  }, 60_000);

  it("leaves the single-player pool as it was: no team story counts toward a pool's size", () => {
    const soloView = ATTACK_STORIES.filter(s => !s.teamOnly);
    for (const c of COMPANIES) for (const d of DIFFS) {
      const solo = storiesForCompany(c, d, true);
      expect(solo.filter(s => s.teamOnly).map(s => s.id)).toEqual([]);
      expect(solo.filter(s => s.soloCompanies && !s.soloCompanies.includes(c)).map(s => s.id)).toEqual([]);
      expect(solo.every(s => soloView.includes(s))).toBe(true);
    }
    // QuantumBank has fewer than eight advanced stories alone, so Hard broadens to core.
    expect(storiesForCompany("quantumbank", "hard", true).some(s => s.complexity === "core")).toBe(true);
  });

  it("widened stories keep their old list for single player", () => {
    const widened = ATTACK_STORIES.filter(s => s.soloCompanies && !s.id.startsWith("ai-") && !s.id.startsWith("web-"));
    expect(widened.length).toBeGreaterThanOrEqual(10);
    for (const s of widened) expect(s.companies!.length).toBeGreaterThan(s.soloCompanies!.length);
  });

  describe("review findings stay fixed", () => {
    it("keeps each process of one image apart, in the row and in the record the client renders", () => {
      for (const c of ["nexacorp", "medcore"]) {
        const r = rows("core-wmi-remote-exec", c);
        const cmds = ["cwm03", "cwm05", "cwm06", "cwm07"].map(i => r.get(i)!);
        expect(new Set(cmds.map(b => b.process?.pid)).size).toBe(4);
        if (c === "nexacorp") for (const b of cmds) expect(props(nativeOf(b, c)).ProcessId).toBe(b.process?.pid);
      }
      const v = rows("core-teams-helpdesk-vishing", "nexacorp");
      expect(v.get("ctv01")!.process?.pid).not.toBe(v.get("ctv05")!.process?.pid);
    });

    it("gives a split parent the same pid on its child's alert and on its own row", () => {
      const r = rows("core-byovd-edr-killer", "nexacorp");
      expect(r.get("cbv09")!.process?.parent_pid ?? r.get("cbv02")!.process?.parent_pid).toBe(r.get("cbv01b")!.process?.pid);
    });

    it("never draws a canary, role or desk account as the victim", () => {
      for (const c of COMPANIES) for (const id of ["core-dll-sideload", "core-byovd-edr-killer"]) {
        const pool = c === "nexacorp" ? BENIGN_EVENTS : COMPANY_EVENTS[c];
        const s = ATTACK_STORIES.find(x => x.id === id)!;
        for (let i = 0; i < 40; i++) {
          const story = instantiateStory(s, pool, undefined, c, () => i / 40);
          for (const e of story.events) expect(e.user_email ?? "").not.toMatch(/sec-canary|^dba@|security-admin|-desk\d*@|^helpdesk@|shift/);
        }
      }
    });

    it("keeps a second person distinct from the victim", () => {
      for (const seed of ["a", "b", "c", "d", "e", "f"]) {
        const r = rows("core-device-code-phish", "nexacorp", seed);
        expect(r.get("cdc13")!.user_email).not.toBe(r.get("cdc12")!.user_email);
      }
    });

    it("gives each AWS tenant its own account, and the outside share reads as outside", () => {
      const seen = new Set<string>();
      for (const c of ["rocketstack", "globallogis", "quantumbank"]) {
        const b = rows("core-ebs-snapshot-share", c).get("ceb04")!;
        const rec = nativeOf(b, c)!;
        const account = String(rec.recipientAccountId);
        seen.add(account);
        expect(JSON.stringify(rec.requestParameters)).toContain("730416259183");
        expect(account).not.toBe("730416259183");
        expect(JSON.stringify(rec)).not.toContain("418772153604");
      }
      expect(seen.size).toBe(3);
    });

    it("shows the client, never the target, on a logon and share record", () => {
      for (const c of ["nexacorp", "medcore", "globallogis"]) {
        const r = rows("core-wmi-remote-exec", c);
        const source = r.get("cwm01a")!, target = r.get("cwm03")!;
        expect(source.src_ip).not.toBe(target.src_ip);
        for (const id of ["cwm02", "cwm04", "cwm08", "cwm09"]) expect(r.get(id)!.src_ip).toBe(source.src_ip);
        expect(r.get("cwm02")!.raw["winlog.event_data.WorkstationName"]).toBe(source.hostname);
        expect(r.get("cwm03")!.process?.cmdline).toContain("__");
      }
      for (const c of ["nexacorp", "medcore", "globallogis"]) {
        const r = rows("core-shadow-credentials", c);
        for (const id of ["csc02l", "csc05", "csc06", "csc07"]) expect(r.get(id)!.src_ip).toBe(r.get("csc02")!.src_ip);
      }
      // A single-player story since the engines stopped sharing them (Tal 2026-11-12): checked on its dashboard render.
      const pth = soloRows("lateral-movement-pth", "nexacorp");
      const hostIps = new Set([...pth.values()].filter(b => b.source !== "windows_security" && b.hostname === pth.get("evt_lm_02_pth_logon")!.hostname).map(b => b.src_ip));
      expect(hostIps.has(pth.get("evt_lm_02_pth_logon")!.src_ip)).toBe(false);
    });

    it("holds the wildcard pivot: the writer's logon, the DNS answer and the relayed logon name one address", () => {
      for (const c of ["nexacorp", "globallogis"]) {
        const r = rows("core-adidns-wildcard", c);
        const answer = r.get("cad04")!.dns?.response;
        expect(r.get("cad02a")!.src_ip).toBe(answer);
        expect(r.get("cad05")!.src_ip).toBe(answer);
        expect(r.get("cad06")!.src_ip).toBe(answer);
        const node = nativeOf(r.get("cad02")!, c)!;
        expect(node.EventID).toBe(5137);
        expect(node.ObjectClass).toBe("dnsNode");
        expect(node.SubjectLogonId).toBe(nativeOf(r.get("cad02a")!, c)!.TargetLogonId);
        expect(r.get("cad02")!.hostname).toBe(r.get("cad02a")!.hostname);
      }
    });

    it("renders the device registration and the token type natively", () => {
      const r = rows("core-device-code-phish", "nexacorp");
      expect(nativeOf(r.get("cdc08")!, "nexacorp")?.activityDisplayName).toBe("Register device");
      expect(nativeOf(r.get("cdc09")!, "nexacorp")?.activityDisplayName).toBe("Add registered owner to device");
      const pr = nativeOf(r.get("cdc10")!, "nexacorp")!;
      expect(pr.incomingTokenType).toBe("primaryRefreshToken");
      expect(pr.appDisplayName).toBe("Microsoft Authentication Broker");
      expect(pr.resourceDisplayName).toBe("Microsoft Graph");
    });

    it("targets a GPO that reaches member machines, joined to the admin's logon", () => {
      const r = rows("core-gpo-scheduled-task", "nexacorp");
      expect(JSON.stringify([...r.values()].map(b => b.raw))).not.toContain("6AC1786C-016F-11D2-945F-00C04FB984F9");
      const write = nativeOf(r.get("cgp03")!, "nexacorp")!;
      expect(r.get("cgp03")!.src_ip).toBeUndefined();
      expect(write.SubjectLogonId).toBe(nativeOf(r.get("cgp02")!, "nexacorp")!.TargetLogonId);
      expect(write.AttributeSyntaxOID).toBe("2.5.5.12");
      expect(nativeOf(r.get("cgp05")!, "nexacorp")!.AttributeSyntaxOID).toBe("2.5.5.9");
      expect(r.get("cgp08")!.user_email).toBeUndefined();
    });

    it("carries a key credential of the declared length", () => {
      const v = String(rows("core-shadow-credentials", "nexacorp").get("csc03")!.raw["winlog.event_data.AttributeValue"]);
      expect(v.split(":")[1]).toBe("828");
      expect(v.split(":")[2]).toHaveLength(828);
    });

    it("gives the renamed binary's embedded name in a native record on every company", () => {
      for (const c of COMPANIES) {
        const b = rows("core-dll-sideload", c).get("csl04s")!;
        expect(JSON.stringify(nativeView(b, c, {})?.log)).toContain("GUP.exe");
      }
    });

    it("keeps Windows paths whole when the EDR name is swapped", () => {
      for (const c of ["rocketstack", "globallogis"]) expect(JSON.stringify(rows("core-byovd-edr-killer", c).get("cbv11")!.raw)).toContain("Microsoft\\\\Windows Defender");
    });

    it("runs the developer stories on developers", () => {
      const seats: Record<string, RegExp> = { nexacorp: /WS-ENG-2093/, rocketstack: /WS-ENG-3301|LAP-DEV-/, quantumbank: /LAP-QB-2290/ };
      expect(offered("medcore", "core-ide-extension-theft")).toEqual([]);
      expect(offered("globallogis", "core-ide-extension-theft")).toEqual([]);
      for (const [c, host] of Object.entries(seats)) expect(rows("core-ide-extension-theft", c).get("cid03")!.hostname).toMatch(host);
    });

    it("takes a story off a company where it makes no sense", () => {
      const has = (id: string, c: string) => ATTACK_STORIES.find(s => s.id === id)!.companies?.includes(c);
      for (const [id, c] of [["webshell-rce", "medcore"], ["webshell-rce", "globallogis"], ["infostealer-session-theft", "rocketstack"], ["rocketstack-chain-a", "quantumbank"], ["rocketstack-chain-d", "quantumbank"],
        ["rocketstack-chain-b", "globallogis"], ["rocketstack-chain-b", "quantumbank"], ["lateral-movement-pth", "quantumbank"], ["windows-privesc-token", "quantumbank"], ["core-wmi-remote-exec", "quantumbank"],
        ["core-rmm-first-stage", "rocketstack"], ["core-thread-hijack-smuggling", "rocketstack"]]) expect(has(id, c), `${id} on ${c}`).toBeFalsy();
    });

    it("deals no single-player story a company list was widened for (the engines share none, Tal 2026-11-12)", () => {
      for (const [id, c] of [["nexacorp-chain-c", "globallogis"], ["nexacorp-chain-c", "quantumbank"], ["rs-terraform-iac-backdoor", "quantumbank"], ["nexacorp-chain-b", "quantumbank"],
        ["exfil-first-extortion", "quantumbank"], ["rs-cicd-pipeline-poisoning", "globallogis"], ["globallogis-chain-d", "rocketstack"]]) expect(offered(c, id), `${id} on ${c}`).toEqual([]);
    });

    it("carries no real public address for the office", () => {
      for (const id of ["core-device-code-phish", "core-azure-cloud-extortion"]) expect(JSON.stringify([...rows(id, "nexacorp").values()])).not.toContain("217.177.80.10");
      expect(JSON.stringify(rows("core-teams-helpdesk-vishing", "nexacorp").get("ctv06"))).not.toContain("13.107.246.60");
    });
  });

  it("runs at least the identity and endpoint stories on the default named-organization environment", () => {
    const fits = teamStoryFilter(TENANT_TEMPLATE, {}, DEFAULT_ENV);
    const pool = new Set(DIFFS.flatMap(d => teamStoryPool(TENANT_TEMPLATE, d, DEFAULT_ENV).filter(fits).map(x => x.id)));
    expect(CORE_STORIES.filter(s => !/s3|ebs/.test(s.id) && !pool.has(s.id)).map(s => s.id)).toEqual([]);
  });
});
