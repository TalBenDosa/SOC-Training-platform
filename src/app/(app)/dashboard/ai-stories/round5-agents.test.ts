import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { nativeView, applyStack, NATIVE_SOURCES, COMPANY_STACKS } from "@/lib/logs/native";
import { validateNative } from "@/lib/logs/native/validate";
import { NOT_SENTINEL, stackForConsole } from "@/lib/team/investigationConsole";
import type { TelemetryEvent } from "@/lib/sim/types";
import { ATTACK_STORIES } from "../attackStories";
import { AI_R5_AGENT_STORIES } from "./round5-agents";

const XDR = stackForConsole({}, "sentinel");
const ips = (evs: TelemetryEvent[]) => new Set(evs.flatMap(e => [e.src_ip, e.dst_ip]).filter((x): x is string => !!x && !/^10\./.test(x)));
const users = (evs: TelemetryEvent[]) => new Set(evs.map(e => e.user_email).filter((x): x is string => !!x));

describe("AI round: agent families", () => {
  it("four stories, two families, one single-player and one Team Training variant each", () => {
    expect(AI_R5_AGENT_STORIES).toHaveLength(4);
    for (const fam of ["ai-toxic-agent-flow", "ai-output-handling"]) {
      const v = AI_R5_AGENT_STORIES.filter(s => s.family === fam);
      expect(v.map(s => s.mode).sort(), fam).toEqual(["solo", "team"]);
      const cat = v.map(s => ATTACK_STORIES.find(x => x.id === s.id)!);
      expect(cat.every(s => s?.family === fam), fam).toBe(true);
      expect(cat.find(s => s.id === v.find(x => x.mode === "team")!.id)!.teamOnly, fam).toBe(true);
      expect(cat.find(s => s.id === v.find(x => x.mode === "solo")!.id)!.teamOnly ?? false, fam).toBe(false);
    }
  });

  it("the two variants of a family share no person and no outside address", () => {
    for (const fam of ["ai-toxic-agent-flow", "ai-output-handling"]) {
      const [a, b] = AI_R5_AGENT_STORIES.filter(s => s.family === fam);
      expect([...ips(a.events)].filter(x => ips(b.events).has(x)), fam).toEqual([]);
      expect([...users(a.events)].filter(x => users(b.events).has(x)), fam).toEqual([]);
    }
  });

  it("every story has a benign look-alike, an incident id and a description on every row", () => {
    for (const s of AI_R5_AGENT_STORIES) {
      expect(s.events.some(e => e.expected_verdict === "fp" && e.fp_explanation), s.id).toBe(true);
      for (const e of s.events) {
        expect(e.incident_id, e.id).toBeTruthy();
        expect((e.description ?? "").length, e.id).toBeGreaterThan(15);
        expect(JSON.stringify(e), e.id).not.toContain(String.fromCharCode(0x2014));
      }
    }
  });

  for (const s of AI_R5_AGENT_STORIES) {
    it(`renders in each listed company's products with zero native violations (${s.id})`, () => {
      const problems: string[] = [];
      for (const c of s.companies) {
        const stack = COMPANY_STACKS[c] ?? {};
        for (const e of s.events) {
          const view = nativeView(applyStack(e, c, stack), c, stack);
          if (!view) continue;
          const v = validateNative(view.log, NATIVE_SOURCES[view.log.sourceId]!.schema);
          if (v.length) problems.push(`${c} ${e.id} ${view.log.sourceId}: ${JSON.stringify(v).slice(0, 200)}`);
        }
      }
      expect(problems).toEqual([]);
    });
  }

  for (const s of AI_R5_AGENT_STORIES.filter(x => x.mode === "team")) {
    it(`renders only Sentinel-world products in an XDR session (${s.id})`, () => {
      const foreign: string[] = [];
      for (const c of s.companies) for (const e of s.events) {
        const id = nativeView(applyStack(e, c, XDR), c, XDR)?.log.sourceId;
        if (id && NOT_SENTINEL.has(id)) foreign.push(`${c} ${e.id} as ${id}`);
      }
      expect(foreign).toEqual([]);
    });
  }

  it("GitHub rows render as the GitHub audit log, with the token and the public repository", () => {
    const pr = AI_R5_AGENT_STORIES[0].events.find(e => e.id === "ai5ta14")!;
    const view = nativeView(pr, "nexacorp")!;
    expect(view.log.sourceId).toBe("github_audit");
    expect(view.log.record).toMatchObject({ action: "pull_request.create", public_repo: true, programmatic_access_type: "Fine-grained personal access token", user_programmatic_access_name: "assistant-mcp" });
    expect(String(view.log.record.pull_request_url)).toMatch(/\/pull\/219$/);
    const flip = AI_R5_AGENT_STORIES[1].events.find(e => e.id === "ai5tb08")!;
    expect(nativeView(flip, "nexacorp")!.log.record).toMatchObject({ action: "repo.access", visibility: "public", previous_visibility: "private" });
  });
});
