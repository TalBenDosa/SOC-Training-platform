/**
 * Scenario review 2026-10-01, fix 4: the twist ("a host you already worked is now
 * beaconing") landed on an unrelated workstation when the story had no host (an
 * account takeover is all cloud logs). It now lands on the victim's own device and
 * says so; and the beacon log carries its process context (the DLL on rundll32's
 * command line is the evidence: rundll32 itself is a clean Microsoft binary).
 *
 * 2026-11-07: the twist rotates among several kinds (msel.ts); every kind is checked for its own
 * coherent rows and text.
 *
 * 2026-11-08 (Sdema review K4, "the twist has no cause"): a C2 implant or a new admin account landed on
 * the DC after a spray that never got in. Each twist kind now follows from what the story ACHIEVED: an
 * implant, persistence, a backdoor account or a remote session only where code ran (or an account logged
 * on), credential reuse only after a sign-in worked, and a story of failures only gets the spray resuming.
 * The account-takeover test used to force a beacon onto the victim's laptop; a cloud takeover runs no code
 * there, so that twist is now dropped for it and the takeover gets the credential-reuse twist instead.
 */
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { buildTeamTimeline } from "./buildTimeline";
import { teamLoad } from "./load";
import { TWIST_KINDS, buildTwist, twistGround, type TwistCtx } from "./msel";
import { ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import type { TelemetryEvent } from "@/lib/sim/types";
import { nativeView } from "@/lib/logs/native";

// A cloud account takeover with no code run (a Team Training story: the engines share none, Tal 2026-11-12).
const impId = "core-device-code-phish";
const EXEC_STORY = "tech-support-scam";
const SPRAY_STORY = "nexacorp-chain-d";
// A web injection story attacked from outside: the operator's return (web_return) lands on its own site.
const WEB_STORY = "web-inj-cmdi-pdfexport";
const tl = (seed: string, storyId?: string, twist?: string) => buildTeamTimeline("nexacorp", "medium", seed, storyId ?? null, teamLoad("medium", [{ role: "t1" }, { role: "t3" }]), {}, null, null, twist ? { force: { twist } } : {});
const twistOf = (t: ReturnType<typeof tl>) => ({
  inject: t.find(e => (e.answer as { original_id?: string } | undefined)?.original_id === "msel_twist"),
  edr: t.find(e => String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").startsWith("msel_twist_edr")),
  rows: t.filter(e => (e.answer as { supports_inject?: string } | undefined)?.supports_inject === "msel_twist"),
});
const idOf = (e: { answer?: unknown }) => String((e.answer as { original_id?: string } | undefined)?.original_id ?? "");
const lcg = (seed: number) => { let x = seed; return () => ((x = (x * 16807) % 2147483647) / 2147483647); };

describe("the twist", () => {
  it("an account-takeover story: no implant on a device nothing ran on; the stolen account is reused, and the inject names it", () => {
    for (const seed of ["e90b31d5", "a", "b"]) {
      expect(twistOf(tl(seed, impId, "second_implant")).inject, "a beacon with no cause").toBeUndefined();
      expect(twistOf(tl(seed, impId, "new_persistence")).inject, "persistence with no cause").toBeUndefined();
      const t = tl(seed, impId, "credential_reuse");
      const { inject, rows } = twistOf(t);
      expect(inject).toBeTruthy();
      const victim = String(rows[0].body.user_email ?? "");
      expect(victim).toMatch(/@/);
      expect(String(inject!.body.text)).toContain(victim.split("@")[0]);
      // the account really is the story's victim: a story log of theirs names it
      expect(t.some(e => e.channel === "feed" && e.body.user_email === victim && !idOf(e).startsWith("msel_"))).toBe(true);
    }
  });

  it("the beacon log names its loader and payload, from a real user profile, ProgramData or Windows\\Temp; a DLL it loads was written first", () => {
    const cmds = new Set<string>();
    for (const seed of ["e90b31d5", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11"]) {
      const t = tl(seed, EXEC_STORY, "second_implant");
      const { edr, rows } = twistOf(t);
      const raw = edr!.body.raw as Record<string, string>;
      const cmd = raw["InitiatingProcessCommandLine"] ?? raw["process.command_line"];
      // The payload: the DLL on a loader's command line, else the image itself (the story's own process).
      const where = `${raw["process.executable"] ?? ""} ${cmd}`;
      expect(where).toMatch(/(\\Users\\[^\\]+\\(AppData\\(Local|Roaming)|Downloads)\\|\\ProgramData\\|\\Windows\\Temp\\)/);
      expect(where).not.toMatch(/\\Users\\Public\\/i);
      const dll = /\s"?([A-Z]:\\[^",]+\.dll)/i.exec(cmd)?.[1];
      if (/rundll32/.test(cmd)) expect(cmd).toMatch(/\.dll,\w+$/);
      if (dll) {
        const drop = rows.find(r => idOf(r).startsWith("msel_twist_drop"));
        expect(drop, `${seed}: no file row for ${dll}`).toBeTruthy();
        expect((drop!.body.file as { path?: string }).path).toBe(dll);
        expect(drop!.due_offset_ms).toBeLessThan(edr!.due_offset_ms);
      }
      // one pid per process: no raw copy contradicts the row's process.pid
      const pid = (edr!.body.process as { pid?: number }).pid;
      for (const k of ["process.pid", "InitiatingProcessId", "ProcessId"]) if (raw[k] !== undefined) expect(Number(raw[k])).toBe(pid);
      cmds.add(cmd);
    }
    expect(cmds.size).toBeGreaterThan(4);   // the loader line differs session to session
  });

  // nexacorp-chain-d (Sdema review K5) now gets in: m.torres's password works (4624 type 3 on the RDS host)
  // and a Remote Desktop session follows. Nothing ran there, so no implant, persistence or backdoor account;
  // a logon that worked carries a remote session or the reuse of that account. The spray that never gets in
  // (spray_resumes) is covered on its own rows below: no authored story is made only of failures any more.
  it("a spray that got in with a password: no implant, persistence or backdoor account; a twist that follows from the logon", () => {
    for (const seed of ["sdema-1", "sdema-a", "sdema-b", "sdema-c"]) {
      for (const k of ["second_implant", "new_persistence", "new_account"]) {
        expect(twistOf(tl(seed, SPRAY_STORY, k)).inject, `${seed} ${k}`).toBeUndefined();
      }
      const { inject, rows } = twistOf(tl(seed, SPRAY_STORY));
      expect(inject, seed).toBeTruthy();
      expect(rows.length).toBeGreaterThanOrEqual(2);
      expect(JSON.stringify(rows)).not.toMatch(/rundll32|regsvr32|CurrentVersion\\\\Run/i);
    }
  });

  it("every kind: rows backing it, one incident, after the inject, text names the ground it lands on", () => {
    const built = new Set<string>();
    for (const kind of TWIST_KINDS) {
      for (const story of [undefined, EXEC_STORY, impId, SPRAY_STORY, WEB_STORY]) {
        const t = tl("kinds-1", story, kind);
        const { inject, rows } = twistOf(t);
        if (!inject) continue;   // a kind this incident cannot carry is dropped, never faked
        built.add(kind);
        expect(rows.length).toBeGreaterThanOrEqual(2);
        expect(new Set(rows.map(r => r.answer?.incident_id)).size).toBe(1);
        for (const r of rows) {
          expect(r.answer?.expected_verdict).toBe("tp");
          expect(r.due_offset_ms).toBeGreaterThan(inject.due_offset_ms);
        }
        const text = String(inject.body.text);
        expect(text).not.toMatch(/\{\w+\}/);
        const named = rows.some(r => [r.body.hostname, r.body.user_email, r.body.dst_ip].some(v => typeof v === "string" && (text.includes(v) || text.includes(v.split("@")[0]))));
        expect(named, `${kind}: ${text}`).toBe(true);
        break;
      }
    }
    // spray_resumes needs a story made only of failures (checked on its own rows below); the others all land here.
    for (const k of TWIST_KINDS.filter(k => k !== "spray_resumes")) expect(built.has(k), k).toBe(true);
  });
});

describe("the twist follows from the story's own rows", () => {
  const a = COMPANY_ASSETS.nexacorp;
  const base = (over: Partial<TwistCtx>): TwistCtx => ({
    rnd: lcg(7), baseTs: "2026-01-01T08:00:00.000Z", assets: a, stack: { onprem_ad: "ad" } as never,
    host: a.dc, hostIp: `${a.subnet}.5`, seenHost: true, edr: "Microsoft Defender for Endpoint", fw: { flavour: "pan", vendor: "Palo Alto Networks PAN-OS" },
    useSysmon: false, ips: new Set(), domains: new Set(), usedHosts: new Set(), os: "windows", companyId: "nexacorp", ...over,
  });
  const fail = (user: string, k: number): TelemetryEvent => ({ id: `f${k}`, ts: "2026-01-01T07:50:00.000Z", source: "ad", vendor: "Windows Security", event_type: "auth_failure",
    hostname: a.dc, src_ip: "185.220.101.45", raw: { "winlog.event_data.TargetUserName": user } } as TelemetryEvent);
  const spray = ["r.avraham", "m.levi", "d.cohen", "j.chen"].map(fail);

  it("failures only: only the spray resumes, its new wave tries the story's own accounts, and a hit is one of them", () => {
    const g = twistGround(base({ story: spray }));
    expect(g).toMatchObject({ exec: false, logon: false, signin: false, failedOnly: true, sprayIp: "185.220.101.45" });
    expect(g.sprayed).toEqual(["r.avraham", "m.levi", "d.cohen", "j.chen"].map(u => `${u}@${a.domain}`));
    for (const k of TWIST_KINDS.filter(k => k !== "spray_resumes")) expect(buildTwist(base({ story: spray }), { twists: {}, injects: {} }, k), k).toBeNull();
    let hits = 0;
    for (let s = 1; s < 12; s++) {
      const tw = buildTwist(base({ story: spray, rnd: lcg(s * 7919) }), { twists: {}, injects: {} })!;
      expect(tw.kind).toBe("spray_resumes");
      const hit = tw.rows.find(r => r.event_type === "auth_success");
      if (hit) { hits++; expect(g.sprayed).toContain(hit.user_email); }
      for (const r of tw.rows) expect(r.src_ip).not.toBe("185.220.101.45");
    }
    expect(hits).toBeGreaterThan(0);
  });

  it("a server nobody works at: no Explorer parent, no profile folder, no Run key", () => {
    const story = [{ id: "p1", ts: "2026-01-01T07:50:00.000Z", source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create", hostname: a.fileServer,
      process: { name: "svchelper.exe", pid: 4412, path: "C:\\ProgramData\\svchelper.exe" } } as TelemetryEvent];
    for (let s = 1; s < 30; s++) {
      for (const k of ["second_implant", "new_persistence"]) {
        const tw = buildTwist(base({ host: a.fileServer, story, rnd: lcg(s * 104729) }), { twists: {}, injects: {} }, k)!;
        expect(tw, k).toBeTruthy();
        const text = JSON.stringify(tw.rows);
        expect(text).not.toMatch(/explorer\.exe/i);
        expect(text).not.toMatch(/\\\\Users\\\\/);
        expect(text).not.toMatch(/CurrentVersion\\\\Run/);
      }
    }
  });
});

describe("a web story's twist: the operator returns", () => {
  it("from a new address, blocked on the request it used, then let through double-encoded, and every row renders natively", () => {
    for (const c of ["nexacorp", "rocketstack"]) {
      const t = buildTeamTimeline(c, "medium", `web-return-${c}`, WEB_STORY, teamLoad("medium", [{ role: "t1" }, { role: "t3" }]), {}, null, null, { force: { twist: "web_return" } });
      const { inject, rows } = twistOf(t);
      expect(inject, c).toBeTruthy();
      const bodies = rows.map(r => r.body as unknown as TelemetryEvent);
      const own = new Set(ATTACK_STORIES.find(s => s.id === WEB_STORY)!.events.map(e => e.id));
      const storyRows = t.filter(r => own.has(idOf(r).replace(/__\d+$/, "")));
      expect(storyRows.length).toBeGreaterThan(5);
      const storyIps = new Set(storyRows.map(r => (r.body as unknown as TelemetryEvent).src_ip));
      const ip = bodies[0].src_ip!;
      expect(storyIps.has(ip), `${c}: ${ip} is the story's own address`).toBe(false);
      expect(String(inject!.body.text)).toContain(ip);
      const [blocked, passed, origin] = bodies;
      expect(blocked.event_type).toBe("waf_block");
      expect(passed.event_type).toBe("waf_allow");
      expect(passed.network?.url).toMatch(/%25[0-9A-F]{2}/i);
      expect(origin.source).toBe("web_server");
      for (const b of bodies) expect(nativeView(b, c), `${c} ${b.id}`).toBeTruthy();
    }
  });
});
