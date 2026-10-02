// A named organization's environment decides its attack arsenal and the platform noise its feed carries.
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { sanitizeEnv, envFromConfig, envAllowsStory, storyIndustry, platformsOfEvent, DEFAULT_ENV, PLATFORM_CHOICES, type TeamEnv } from "./environment";
import { teamStoryPool, teamStoryFilter, buildTeamTimeline, resolveTeamStory } from "./buildTimeline";
import { teamLoad } from "./load";
import { ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";
import { TENANT_TEMPLATE } from "./tenant";
import type { TelemetryEvent } from "@/lib/sim/types";

const ALL = PLATFORM_CHOICES.map(p => p.id);
const story = (id: string) => ATTACK_STORIES.find(s => s.id === id)!;
const offered = (env: TeamEnv, stack = {}) => {
  const fits = teamStoryFilter(TENANT_TEMPLATE, stack, env);
  return new Set((["easy", "medium", "hard"] as const).flatMap(d => teamStoryPool(TENANT_TEMPLATE, d, env, stack).filter(fits).map(s => s.id)));
};

describe("environment input", () => {
  it("keeps known platforms / industry only and defaults the rest", () => {
    expect(sanitizeEnv(null)).toEqual(DEFAULT_ENV);
    expect(sanitizeEnv({ platforms: ["aws", "bogus", "k8s"], industry: "casino" })).toEqual({ platforms: ["aws", "k8s"], industry: "general" });
    expect(sanitizeEnv({ platforms: [], industry: "healthcare" })).toEqual({ platforms: [], industry: "healthcare" });
  });
  it("exists only for a named-organization session", () => {
    expect(envFromConfig({ stack: {} })).toBeNull();
    expect(envFromConfig({ tenant: { name: "acme" } })).toEqual(DEFAULT_ENV);
    expect(envFromConfig({ tenant: { name: "acme" }, env: { platforms: ["aws"], industry: "finance" } })).toEqual({ platforms: ["aws"], industry: "finance" });
  });
});

describe("the arsenal follows the environment", () => {
  it("platform stories need the platform", () => {
    const noAws: TeamEnv = { platforms: ["azure", "linux"], industry: "general" };
    expect(envAllowsStory(noAws, story("rocketstack-chain-a"))).toBe(false);        // S3 exfil needs AWS
    expect(envAllowsStory({ ...noAws, platforms: [...noAws.platforms, "aws"] }, story("rocketstack-chain-c"))).toBe(true);
    expect(envAllowsStory(noAws, story("k8s-pod-escape"))).toBe(false);
    expect(envAllowsStory({ platforms: ALL, industry: "general" }, story("k8s-pod-escape"))).toBe(true);
    expect(envAllowsStory({ platforms: ["linux"], industry: "general" }, story("nexacorp-chain-a"))).toBe(false);   // Key Vault needs Azure
  });
  it("industry stories need the industry", () => {
    expect(storyIndustry("medcore-chain-a")).toBe("healthcare");
    expect(storyIndustry("qb-swift-wire-fraud")).toBe("finance");
    expect(storyIndustry("phishing-malware")).toBe("general");
    const all: TeamEnv = { platforms: ALL, industry: "general" };
    expect(offered(all).has("medcore-chain-a")).toBe(false);
    expect(offered({ ...all, industry: "healthcare" }).has("medcore-chain-a")).toBe(true);
    expect(offered({ ...all, industry: "healthcare" }).has("qb-swift-wire-fraud")).toBe(false);
  });
  it("opens the Microsoft-world stories the old company fit hid", () => {
    const def = offered(DEFAULT_ENV);
    for (const id of ["dcsync", "oauth", "insider", "bruteforce-single", "ransomware"]) expect(def.has(id), id).toBe(true);
    const ndr = offered({ ...DEFAULT_ENV, platforms: [...DEFAULT_ENV.platforms, "ndr"] });
    for (const id of ["asrep-roasting", "ntlm-relay"]) expect(ndr.has(id), id).toBe(true);
  });
  it("product-specific stories follow the chosen products", () => {
    const all: TeamEnv = { platforms: ALL, industry: "general" };
    expect(offered(all).has("okta-password-burst")).toBe(false);                    // an Entra shop
    expect(offered(all, { idp: "okta" }).has("okta-password-burst")).toBe(true);
    expect(offered(all).has("edge-vpn-cve-exploit")).toBe(false);                   // a FortiOS CVE on a GlobalProtect shop
    expect(offered(all, { vpn: "fortigate_sslvpn", firewall: "fortigate" }).has("edge-vpn-cve-exploit")).toBe(true);
  });
  it("a pinned storyline outside the environment is refused", () => {
    expect(resolveTeamStory(TENANT_TEMPLATE, "medium", "rocketstack-chain-a", DEFAULT_ENV)).toBeNull();
    expect(resolveTeamStory(TENANT_TEMPLATE, "medium", "rocketstack-chain-a", { platforms: ["aws"], industry: "general" })?.id).toBe("rocketstack-chain-a");
  });
});

describe("the feed carries the platforms the organization runs — and only those", () => {
  const feedOf = (env: TeamEnv) => buildTeamTimeline(TENANT_TEMPLATE, "medium", "env-noise", null, teamLoad("medium", [{ role: "t1" }, { role: "t2" }]), {}, null, env)
    .filter(t => t.channel === "feed" && (t.answer as { origin?: string })?.origin === "noise").map(t => t.body as unknown as TelemetryEvent);
  it("ordinary AWS traffic when AWS is run, none when it is not", () => {
    const withAws = feedOf({ platforms: ["azure", "aws"], industry: "general" });
    expect(withAws.some(e => platformsOfEvent(e).includes("aws"))).toBe(true);
    const without = feedOf({ platforms: ["azure"], industry: "general" });
    expect(without.some(e => platformsOfEvent(e).length && !platformsOfEvent(e).every(p => p === "azure"))).toBe(false);
  });
});
