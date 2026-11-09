/**
 * XDR alerts carry their evidence (LOG-REALISM-STANDARD R7) and come after it (R4), in the stack the
 * XDR console really runs (Defender for Endpoint + the Graph alert feed, stackForConsole "sentinel"),
 * for every company, with the feed re-timed to its release as the XDR window re-times it:
 *  - every alert's "Events" query runs and returns rows;
 *  - an alert raised on a feed log that has a row of its own returns that row;
 *  - StartTime <= EndTime <= TimeGenerated on every SecurityAlert row, and an incident is created no
 *    earlier than its first alert's evidence;
 *  - every account an alert names is spelled as the feed spells it (one UPN per person, R3).
 */
import { describe, expect, it } from "vitest";
import { runKql } from "@/lib/kql";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import { stackForConsole } from "@/lib/team/investigationConsole";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildWorkspace } from "./workspace";

const COMPANIES = ["nexacorp", "medcore", "rocketstack", "globallogis", "quantumbank"];
const ROSTER = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
const STACK = stackForConsole({}, "sentinel");
const T0 = Date.parse("2026-11-09T08:00:00Z");

describe("XDR alerts open on their evidence", () => {
  for (const company of COMPANIES) {
    it(`${company}: every alert returns its rows, its own log among them, and comes after them`, () => {
      const tl = buildTeamTimeline(company, "hard", `xdr-evidence-${company}`, null, teamLoad("hard", ROSTER), STACK).filter(t => t.channel === "feed");
      const events = tl.map(t => withRebasedTime(t.body as unknown as TelemetryEvent, new Date(T0 + t.due_offset_ms).toISOString()));
      const ws = buildWorkspace(events, { companyId: company, stack: STACK });
      const env = { tables: ws.tables, now: new Date(ws.now) };
      const problems: string[] = [];
      expect(ws.alerts.length).toBeGreaterThan(0);
      for (const a of ws.alerts) {
        const r = runKql(a.query, env);
        if (!r.ok) { problems.push(`${a.name}: ${r.error.message}`); continue; }
        if (!r.rows.length) { problems.push(`${a.name}: the Events query returns nothing`); continue; }
        // The log the alert was raised on, when it has a row of its own, is part of what "Events" returns.
        const own = (ws.alertEventIds[a.id] ?? []).flatMap(id => ws.eventRows[id] ?? []).filter(m => m.table !== "SecurityAlert");
        const at = (v: unknown) => (v instanceof Date ? v.getTime() : Date.parse(String(v)));
        if (own.length && !own.some(m => r.rows.some(x => at(x.TimeGenerated) === at(m.row.TimeGenerated) && (x.Type ?? m.row.Type) === m.row.Type)))
          problems.push(`${a.name}: the Events query does not return the alert's own ${own[0].table} row`);
      }
      for (const row of ws.tables.SecurityAlert.rows) {
        const s = Date.parse(String(row.StartTime)), e = Date.parse(String(row.EndTime)), g = Date.parse(String(row.TimeGenerated));
        if (!(s <= e && e <= g + 1000)) problems.push(`${row.AlertName}: StartTime ${row.StartTime} EndTime ${row.EndTime} TimeGenerated ${row.TimeGenerated}`);
      }
      const startOf = new Map(ws.tables.SecurityAlert.rows.map(r => [String(r.SystemAlertId), Date.parse(String(r.StartTime))]));
      for (const inc of ws.incidents) {
        const first = Math.min(...inc.alertIds.map(id => startOf.get(id) ?? Infinity));
        if (Number.isFinite(first) && Date.parse(inc.created) + 1000 < first) problems.push(`incident ${inc.number} created ${inc.created} before its evidence ${new Date(first).toISOString()}`);
      }
      // R3: an account entity is one of the feed's spellings of that person.
      const feedUsers = new Set(events.flatMap(e => [e.user_email, e.user?.email]).filter((u): u is string => !!u).map(u => u.toLowerCase()));
      const feedSams = new Set([...feedUsers].map(u => u.split("@")[0]));
      const feedText = JSON.stringify(events).toLowerCase();
      for (const en of Object.values(ws.entities)) {
        if (en.kind !== "account") continue;
        const n = en.name.toLowerCase();
        const sam = n.split("@")[0].split("\\").pop()!;
        // A person the feed names (user field or a raw account field), or a built-in principal.
        if (!feedUsers.has(n) && !feedSams.has(sam) && !feedText.includes(sam) && !/^(system|local service|network service|anonymous logon|admin|administrator|root)$/.test(n))
          problems.push(`account entity ${en.name} is spelled as no feed row spells a user`);
      }
      expect([...new Set(problems)].slice(0, 20)).toEqual([]);
    }, 120_000);
  }
});
