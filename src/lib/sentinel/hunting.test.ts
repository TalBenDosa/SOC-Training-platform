// Hunting queries and insights run through the engine over real feeds.
import { describe, expect, it } from "vitest";
import { runKql } from "@/lib/kql";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildHunting } from "./hunting";
import { entityInsights, incidentInsights } from "./insights";
import { columnType, TABLE_NAMES } from "./tables";
import { buildWorkspace } from "./workspace";

const COMPANIES = ["nexacorp", "medcore", "rocketstack", "globallogis", "quantumbank"];
const roster = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
const workspace = (company: string, seed: string) => {
  const events = buildTeamTimeline(company, "hard", seed, null, teamLoad("hard", roster), {}).filter(t => t.channel === "feed").map(t => t.body as unknown as TelemetryEvent);
  return buildWorkspace(events, { companyId: company });
};

describe("hunting queries", () => {
  it("at least 20, across identity, endpoint, email, cloud and network", () => {
    const list = buildHunting();
    expect(list.length).toBeGreaterThanOrEqual(20);
    for (const area of ["identity-", "endpoint-", "email-", "cloud-", "network-"]) expect(list.filter(h => h.id.startsWith(area)).length, area).toBeGreaterThanOrEqual(3);
    expect(new Set(list.map(h => h.id)).size).toBe(list.length);
    for (const h of list) {
      expect(h.name.length).toBeGreaterThan(5);
      for (const t of h.dataSources) expect(TABLE_NAMES, t).toContain(t);
      expect(h.query).not.toContain(String.fromCodePoint(0x2014));
    }
  });

  for (const company of COMPANIES) {
    it(`${company}: every query parses and runs`, () => {
      const ws = workspace(company, `hunt-${company}`);
      const env = { tables: ws.tables, now: new Date(ws.now) };
      const problems: string[] = [];
      let withRows = 0;
      for (const h of ws.hunting) {
        const r = runKql(h.query, env);
        if (!r.ok) problems.push(`${h.id}: ${r.error.message} (${r.error.line}:${r.error.column})`);
        else if (r.rows.length) withRows++;
      }
      expect(problems).toEqual([]);
      expect(withRows).toBeGreaterThan(3);
    });
  }

  it("names only real columns of its first table", () => {
    const problems: string[] = [];
    for (const h of buildHunting()) {
      const table = h.dataSources[0];
      const filters = [...h.query.matchAll(/\b([A-Za-z][A-Za-z0-9_]*)\s+(?:==|!=|=~|has|has_any|contains|in~?|startswith|>=|>)\s/g)].map(m => m[1]);
      for (const c of filters) {
        if (["and", "or", "where", "Failures", "Successes", "Accounts", "Ports", "Hosts", "CountryCount", "Length"].includes(c)) continue;
        if (!columnType(table, c)) problems.push(`${h.id}: ${table}.${c}`);
      }
    }
    expect(problems).toEqual([]);
  });
});

describe("insights", () => {
  for (const company of COMPANIES) {
    it(`${company}: every card is a query that returns its preview`, () => {
      const ws = workspace(company, `ins-${company}`);
      const env = { tables: ws.tables, now: new Date(ws.now) };
      let cards = 0;
      for (const inc of ws.incidents.slice(0, 6)) {
        const list = incidentInsights(ws, inc);
        expect(list.length, inc.title).toBeGreaterThan(0);
        for (const c of list) {
          cards++;
          const r = runKql(c.query, env);
          expect(r.ok).toBe(true);
          if (r.ok) expect(r.rows.length).toBeGreaterThanOrEqual(c.preview.rows.length);
          expect(c.preview.columns.length).toBeGreaterThan(0);
        }
      }
      expect(cards).toBeGreaterThan(5);
      const withCards = Object.keys(ws.entities).filter(id => entityInsights(ws, id).length > 0);
      expect(withCards.length).toBeGreaterThan(0);
    });
  }

  it("an unknown entity has no insights", () => {
    expect(entityInsights(workspace("nexacorp", "none"), "host:nope")).toEqual([]);
  });
});
