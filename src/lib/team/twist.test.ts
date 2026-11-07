/**
 * Scenario review 2026-10-01, fix 4: the twist ("a host you already worked is now
 * beaconing") landed on an unrelated workstation when the story had no host (an
 * account takeover is all cloud logs). It now lands on the victim's own device and
 * says so; and the beacon log carries its process context (the DLL on rundll32's
 * command line is the evidence: rundll32 itself is a clean Microsoft binary).
 *
 * 2026-11-07: the twist rotates among five kinds (msel.ts); the beacon tests force the
 * second-implant kind, and every kind is checked for its own coherent rows and text.
 */
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { buildTeamTimeline } from "./buildTimeline";
import { teamLoad } from "./load";
import { TWIST_KINDS } from "./msel";
import { ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";

const impId = ATTACK_STORIES.find(s => s.events.some(e => e.id === "evt_imp_01_baseline"))!.id;
const tl = (seed: string, storyId?: string, twist?: string) => buildTeamTimeline("nexacorp", "medium", seed, storyId ?? null, teamLoad("medium", [{ role: "t1" }, { role: "t3" }]), {}, null, null, twist ? { force: { twist } } : {});
const twistOf = (t: ReturnType<typeof tl>) => ({
  inject: t.find(e => (e.answer as { original_id?: string } | undefined)?.original_id === "msel_twist"),
  edr: t.find(e => String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").startsWith("msel_twist_edr")),
  rows: t.filter(e => (e.answer as { supports_inject?: string } | undefined)?.supports_inject === "msel_twist"),
});

describe("the twist", () => {
  it("an account-takeover story: the twist lands on the victim's own device, and the inject says so", () => {
    for (const seed of ["e90b31d5", "a", "b"]) {
      const t = tl(seed, impId, "second_implant");
      const { inject, edr } = twistOf(t);
      expect(inject).toBeTruthy();
      const host = String(edr!.body.hostname);
      const victim = String(edr!.body.user_email ?? "");
      expect(victim).toMatch(/@/);
      const text = String(inject!.body.text);
      expect(text).toContain(host);
      expect(text).toContain(`${victim.split("@")[0]}'s own device`);
      // the device really is the victim's: a story log of theirs names it
      const named = t.some(e => e.channel === "feed" && e.body.user_email === victim && JSON.stringify(e.body).includes(host) && e !== edr);
      expect(named).toBe(true);
    }
  });

  it("the beacon log names its loader and payload, from a user-writable folder or ProgramData", () => {
    const cmds = new Set<string>();
    for (const seed of ["e90b31d5", "s1", "s2", "s3", "s4", "s5"]) {
      const { edr } = twistOf(tl(seed, impId, "second_implant"));
      const raw = edr!.body.raw as Record<string, string>;
      const cmd = raw["InitiatingProcessCommandLine"] ?? raw["process.command_line"];
      expect(cmd).toMatch(/(\\AppData\\(Local|Roaming)\\|\\ProgramData\\)/);
      if (/rundll32/.test(cmd)) expect(cmd).toMatch(/\.dll,\w+$/);
      cmds.add(cmd);
    }
    expect(cmds.size).toBeGreaterThan(4);   // the loader line differs session to session
  });

  it("every kind: rows backing it, one incident, after the inject, text names the ground it lands on", () => {
    let built = 0;
    for (const kind of TWIST_KINDS) {
      const t = tl("kinds-1", undefined, kind);
      const { inject, rows } = twistOf(t);
      if (!inject) continue;   // a kind this incident cannot carry is dropped, never faked
      built++;
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
    }
    expect(built).toBeGreaterThanOrEqual(4);
  });
});
