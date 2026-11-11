import { describe, expect, it } from "vitest";
import { runKql } from "@/lib/kql";
import { hydrate } from "../kqlCompare";
import { getDataset } from "../datasets";
import { consoleIds, getConsole } from ".";

describe.each(consoleIds())("mission console %s", id => {
  const c = getConsole(id)!;
  const ds = getDataset(c.dataset)!;
  const tables = { ...hydrate(ds.visible), ...hydrate({ now: ds.visible.now, tables: c.tables }) };
  const run = (q: string) => runKql(q, { tables, now: new Date(ds.visible.now) });
  const rows = (q: string) => { const r = run(q); if (!r.ok) throw new Error(`${r.error.message} in:\n${q}`); return r.rows; };

  it("sits on a real dataset", () => expect(ds).toBeTruthy());

  it("every alert, incident, detection and hunt query runs and finds rows", () => {
    for (const a of c.alerts) expect(rows(a.query).length, a.name).toBeGreaterThan(0);
    for (const i of c.incidents) expect(rows(i.eventsQuery).length, `incident ${i.number}`).toBeGreaterThan(0);
    // A detection scoped to its schedule (ago(...)) runs, and finds rows only when it last fired.
    for (const r of c.rules) { const n = rows(r.query).length; if (!r.query.includes("ago(")) expect(n, r.name).toBeGreaterThan(0); }
    for (const h of c.hunting) expect(rows(h.query).length, h.name).toBeGreaterThan(0);
  });

  it("incidents point at alerts and entities that exist", () => {
    const alerts = new Set(c.alerts.map(a => a.id));
    for (const i of c.incidents) {
      for (const a of i.alertIds) expect(alerts.has(a), `${i.number} -> ${a}`).toBe(true);
      for (const e of i.entityIds) expect(c.entities[e], `${i.number} -> ${e}`).toBeTruthy();
    }
    for (const a of c.alerts) {
      for (const e of a.entityIds) expect(c.entities[e], `${a.name} -> ${e}`).toBeTruthy();
      if (a.ruleId) expect(c.rules.some(r => r.id === a.ruleId), a.ruleId).toBe(true);
    }
  });

  it("fictional values only", () => {
    const text = JSON.stringify(c);
    expect(text).not.toMatch(/—/);
    for (const ip of text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? []) expect(ip, ip).toMatch(/^(10\.|192\.168\.|198\.51\.100\.|203\.0\.113\.|192\.0\.2\.)/);
  });
});

describe("clear-sky console story", () => {
  const c = getConsole("clear-sky")!;
  const ds = getDataset("clear-sky")!;
  const tables = hydrate(ds.visible);
  it("the spray detection catches 203.0.113.77 and the shop NAT, and misses the slow spray", () => {
    const rule = c.rules.find(r => r.id === "rule-spray")!;
    const r = runKql(rule.query, { tables, now: new Date(ds.visible.now) });
    expect(r.ok).toBe(true);
    const ips = r.ok ? r.rows.map(x => x.IPAddress).sort() : [];
    expect(ips).toEqual(["198.51.100.10", "203.0.113.77"]);
  });
  it("the forwarding detection ignores the admin's Set-InboxRule", () => {
    const rule = c.rules.find(r => r.id === "rule-forward-rule")!;
    const r = runKql(rule.query, { tables, now: new Date(ds.visible.now) });
    expect(r.ok && r.rows.map(x => x.UserId)).toEqual(["d.okafor@ashgrove.example"]);
  });
});
