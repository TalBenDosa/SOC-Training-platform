/**
 * Scenario review 2026-10-01, fix 4: the twist ("a host you already worked is now
 * beaconing") landed on an unrelated workstation when the story had no host — an
 * account takeover is all cloud logs. It now lands on the victim's own device and
 * says so; and the beacon log carries its process context (the DLL on rundll32's
 * command line is the evidence — rundll32 itself is a clean Microsoft binary).
 */
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { buildTeamTimeline } from "./buildTimeline";
import { teamLoad } from "./load";
import { ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";

const impId = ATTACK_STORIES.find(s => s.events.some(e => e.id === "evt_imp_01_baseline"))!.id;
const tl = (seed: string, storyId?: string) => buildTeamTimeline("nexacorp", "medium", seed, storyId ?? null, teamLoad("medium", [{ role: "t1" }, { role: "t3" }]));
const twistOf = (t: ReturnType<typeof tl>) => ({
  inject: t.find(e => (e.answer as { original_id?: string } | undefined)?.original_id === "msel_twist"),
  edr: t.find(e => String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").startsWith("msel_twist_edr")),
});

describe("the twist", () => {
  it("an account-takeover story: the twist lands on the victim's own device, and the inject says so", () => {
    for (const seed of ["e90b31d5", "a", "b"]) {
      const t = tl(seed, impId);
      const { inject, edr } = twistOf(t);
      expect(inject).toBeTruthy();
      const host = String(edr!.body.hostname);
      const victim = String(edr!.body.user_email ?? "");
      expect(victim).toMatch(/@/);
      const text = String(inject!.body.text);
      expect(text).toContain(host);
      expect(text).toContain(`${victim.split("@")[0]}'s own device`);
      expect(text).not.toMatch(/a host you already worked/);
      // the device really is the victim's: a story log of theirs names it
      const named = t.some(e => e.channel === "feed" && e.body.user_email === victim && JSON.stringify(e.body).includes(host) && e !== edr);
      expect(named).toBe(true);
    }
  });

  it("the beacon log names the DLL rundll32 ran, from a user-writable folder", () => {
    const { edr } = twistOf(tl("e90b31d5", impId));
    const raw = edr!.body.raw as Record<string, string>;
    const cmd = raw["InitiatingProcessCommandLine"] ?? raw["process.command_line"];
    expect(cmd.startsWith('"C:\\Windows\\System32\\rundll32.exe" C:\\Users\\')).toBe(true);
    expect(cmd).toMatch(/\\AppData\\Local\\Temp\\\w+\.dll,DllRegisterServer$/);
    expect(raw["process.parent.name"]).toBe("explorer.exe");
  });

  it("a story with a host the team already saw keeps the original wording", () => {
    let checked = 0;
    for (const seed of ["s1", "s2", "s3", "s4", "s5", "s6"]) {
      const { inject } = twistOf(tl(seed));
      if (!inject) continue;
      const text = String(inject.body.text);
      if (/a host you already worked/.test(text)) checked++;
      else expect(text).toMatch(/own device|has started beaconing/);
    }
    expect(checked).toBeGreaterThan(0);
  });
});
