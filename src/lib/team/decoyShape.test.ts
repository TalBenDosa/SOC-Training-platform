/**
 * Sdema review 2026-11-08, K2: decoys and attacks differed in shape. Decoy EDR rows had 3-4 raw keys
 * against 18-20 on attack rows, decoy sign-ins 15 against 43, and every decoy Sentinel alert was a
 * `risk_score_change` no attack alert ever is: a trainee could score by counting fields. The decoys are
 * now built by the stories' own emitters, so within each (source, event_type) an attack row and a
 * non-attack row carry about as many raw fields (mean raw key count within 30%), over several seeds of
 * the Sdema exercise config.
 */
import { describe, it, expect } from "vitest";
import { buildFittedTimeline } from "./fitTimeline";
import { teamLoad, withShiftMinutes } from "./load";
import { loadWithPlan, planFromConfig } from "./attackPlan";
import { tenantFromConfig } from "./tenant";
import { envFromConfig } from "./environment";

const CONFIG = {
  env: { industry: "general", platforms: ["azure", "linux"] },
  stack: { edr: "mde", detection_feed: "ms_graph" },
  tenant: { name: "sdemagroup" },
  attacks: { bonus: true, count: 3, slots: ["nexacorp-chain-d", "ai-rag-chatbot-document-injection", "ai-helpdesk-voice-reset"] },
};
const SEEDS = ["sdema-1", "sdema-a", "sdema-b", "sdema-c", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12"];

/**
 * Pairs whose gap is in rows other owners emit (review 2026-11-08 split by data source), checked here
 * once their fix lands. Never a pair a decoy or MSEL row of this module is the thin side of.
 *  - ad|auth_failure: the chain-d spray's 4625 rows carry 9 keys (K5, Windows / chain-d owner); the
 *    decoy 4625 is the full Windows Security emitter row.
 *  - soar|policy_modification: a maker's ticket is rendered by itsmNoise.ts ticketRecord, which writes a
 *    shorter ServiceNow envelope than the stories' tickets (ITSM owner).
 *  - cloud_azure|cloud_api_call: an Azure Activity noise row of the pool against the AI stories' Azure
 *    OpenAI rows (Azure owner).
 */
const ELSEWHERE = new Set(["ad|auth_failure", "soar|policy_modification", "cloud_azure|cloud_api_call"]);

describe("decoys have the shape of attacks", () => {
  it("within each (source, event_type), attack and non-attack rows differ in mean raw key count by less than 30%", () => {
    const roster = [{ role: "t1" }, { role: "t2" }, { role: "mgr" }];
    const groups = new Map<string, { atk: number[]; non: number[]; mine: boolean }>();
    for (const seed of SEEDS) {
      const plan = planFromConfig(CONFIG);
      const load = loadWithPlan(withShiftMinutes(teamLoad("medium", roster), 30), plan);
      const { timeline } = buildFittedTimeline({
        companyId: "nexacorp", difficulty: "medium", seed, slots: plan.slots, load,
        stack: CONFIG.stack as never, tenant: tenantFromConfig(CONFIG), env: envFromConfig(CONFIG), opts: { bonus: true }, roster,
      });
      for (const r of timeline) {
        if (r.channel !== "feed" && r.channel !== "bonus") continue;
        const a = (r.answer ?? {}) as { expected_verdict?: string; original_id?: string };
        const b = r.body as { source?: string; event_type?: string; raw?: Record<string, unknown> };
        const key = `${b.source}|${b.event_type}`;
        const g = groups.get(key) ?? groups.set(key, { atk: [], non: [], mine: false }).get(key)!;
        (["tp", "escalate"].includes(String(a.expected_verdict)) ? g.atk : g.non).push(Object.keys(b.raw ?? {}).length);
        if (/^(fpa_|msel_)/.test(String(a.original_id ?? ""))) g.mine = true;
      }
    }
    const mean = (x: number[]) => x.reduce((s, v) => s + v, 0) / x.length;
    const off: string[] = [];
    let compared = 0;
    for (const [key, g] of groups) {
      if (!g.atk.length || !g.non.length) continue;
      compared++;
      const A = mean(g.atk), N = mean(g.non);
      if (Math.abs(A - N) / Math.max(A, N) >= 0.3 && !ELSEWHERE.has(key)) off.push(`${key}: attack ${A.toFixed(1)} vs non-attack ${N.toFixed(1)}${g.mine ? " (decoy / MSEL rows)" : ""}`);
    }
    expect(compared).toBeGreaterThanOrEqual(8);
    expect(off).toEqual([]);
  }, 300_000);
});
