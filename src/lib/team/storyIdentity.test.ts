/**
 * Sdema review 2026-11-08: in the tech-support-scam story the row named one person (user_email) while
 * its process ran as another (the tenant swap chained one template person's new name into another's).
 * One victim is one person in every row of the story: the mailbox, the process account and the
 * account the native EDR record prints.
 */
import { describe, it, expect } from "vitest";
import { buildFittedTimeline } from "./fitTimeline";
import { teamLoad, withShiftMinutes } from "./load";
import { loadWithPlan, planFromConfig } from "./attackPlan";
import { tenantFromConfig } from "./tenant";
import { envFromConfig } from "./environment";
import { nativeView } from "@/lib/logs/native";

const CONFIG = {
  env: { industry: "general", platforms: ["azure", "linux"] },
  stack: { edr: "mde", detection_feed: "ms_graph" },
  tenant: { name: "sdemagroup" },
  attacks: { bonus: true, count: 3, slots: ["nexacorp-chain-d", "ai-rag-chatbot-document-injection", "tech-support-scam"] },
};

describe("one victim is one person across the tech-support-scam story", () => {
  for (const seed of ["sdema-1", "sdema-a", "s5", "s9", "q7", "q21"]) {
    it(`seed ${seed}`, () => {
      const roster = [{ role: "t1" }, { role: "t2" }, { role: "mgr" }];
      const plan = planFromConfig(CONFIG);
      const load = loadWithPlan(withShiftMinutes(teamLoad("medium", roster), 30), plan);
      const { timeline } = buildFittedTimeline({
        companyId: "nexacorp", difficulty: "medium", seed, slots: plan.slots, load,
        stack: CONFIG.stack as never, tenant: tenantFromConfig(CONFIG), env: envFromConfig(CONFIG), opts: { bonus: true }, roster,
      });
      const rows = timeline.filter(r => /^evt_rat_/.test(String((r.answer as { original_id?: string } | undefined)?.original_id)));
      expect(rows.length).toBeGreaterThan(3);
      const people = new Set<string>();
      for (const r of rows) {
        const b = r.body as { user_email?: string; process?: { user?: string }; raw?: Record<string, unknown> };
        if (b.user_email) people.add(b.user_email.split("@")[0]);
        const procUser = b.process?.user?.split("\\").pop();
        if (procUser && !/^SYSTEM$/i.test(procUser)) people.add(procUser);
        const rec = nativeView(b as never, "nexacorp", CONFIG.stack as never)?.log.record as Record<string, unknown> | undefined;
        for (const k of ["AccountName", "InitiatingProcessAccountName"]) {
          const v = rec?.[k];
          if (typeof v === "string" && v && !/^(system|local service|network service)$/i.test(v)) people.add(v);
        }
      }
      expect([...people]).toHaveLength(1);
    });
  }
});
