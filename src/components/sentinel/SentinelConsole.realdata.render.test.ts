// The console on a real exercise: a built timeline through buildWorkspace, as the team room feeds it.
// The fixture cannot catch what depends on the shape of real rows, such as how accounts are stored.
import { describe, it, expect, afterEach, vi } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { SentinelConsole } from "./SentinelConsole";
import { fakeActions } from "./fixture";
import { alertsQuery, bookmarksQuery, entitiesFromRows, explorationsFor } from "./helpers";
import { incidentInsights, entityInsights } from "@/lib/sentinel/insights";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import { buildWorkspace } from "@/lib/sentinel/workspace";
import { foldIncidentState } from "@/lib/sentinel/state";
import { bookmarkTable } from "./helpers";
import { runKql } from "@/lib/kql";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { SentinelWorkspace } from "@/lib/sentinel/types";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
vi.mock("next/navigation", () => ({ useRouter: () => ({ push() {}, replace() {}, back() {} }), usePathname: () => "/sentinel", useSearchParams: () => new URLSearchParams() }));

const ROSTER = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
function exercise(company: string, seed: string): SentinelWorkspace {
  const events = buildTeamTimeline(company, "medium", seed, null, teamLoad("medium", ROSTER), {})
    .filter(t => t.channel === "feed").map(t => t.body as unknown as TelemetryEvent);
  return buildWorkspace(events, { companyId: company });
}

const WS = [exercise("nexacorp", "real-1"), exercise("medcore", "real-2"), exercise("quantumbank", "real-3")];
const run = (ws: SentinelWorkspace, q: string) => runKql(q, { tables: { ...ws.tables, HuntingBookmark: bookmarkTable([]) }, now: new Date(ws.now) });

describe.each(WS.map(ws => [ws.name, ws] as const))("%s", (_name, ws) => {
  it("has something to investigate", () => {
    expect(ws.incidents.length).toBeGreaterThan(0);
  });

  it("every query a link opens parses and runs, and the evidence is there", () => {
    for (const i of ws.incidents) {
      const events = run(ws, i.eventsQuery);
      expect(events.ok, i.eventsQuery).toBe(true);
      if (events.ok) expect(events.rows.length, i.eventsQuery).toBeGreaterThan(0);
      const alerts = run(ws, alertsQuery(i));
      expect(alerts.ok && alerts.rows.length, i.title).toBe(i.alertIds.length);
      expect(run(ws, bookmarksQuery(i)).ok).toBe(true);
    }
    for (const a of ws.alerts) {
      const r = run(ws, a.query);
      expect(r.ok, a.query).toBe(true);
      if (r.ok) expect(r.rows.length, a.query).toBeGreaterThan(0);
    }
  });

  it("every exploration query and insight runs", () => {
    for (const e of Object.values(ws.entities)) {
      for (const x of explorationsFor(e, ws)) expect(run(ws, x.query).ok, x.query).toBe(true);
      for (const i of entityInsights(ws, e.id)) expect(run(ws, i.query).ok, i.query).toBe(true);
    }
    for (const i of ws.incidents) for (const c of incidentInsights(ws, i)) expect(run(ws, c.query).ok, c.query).toBe(true);
  });

  it("Related alerts finds the alerts of every entity, accounts included", () => {
    for (const a of ws.alerts) {
      for (const id of a.entityIds) {
        const e = ws.entities[id];
        const related = explorationsFor(e, ws).find(x => x.id === "related-alerts");
        if (!related || ["process", "registry", "cloudapp", "azureresource"].includes(e.kind)) continue;
        const r = run(ws, related.query);
        expect(r.ok && r.rows.some(x => x.SystemAlertId === a.id), `${e.kind} ${e.name} in ${a.name}`).toBe(true);
      }
    }
  });

  it("maps entities from real rows", () => {
    const withEntities = ws.incidents.find(i => i.entityIds.length > 0);
    if (!withEntities) return;
    const rows = ws.tables.SecurityAlert.rows.filter(r => withEntities.alertIds.includes(String(r.SystemAlertId)));
    expect(entitiesFromRows(rows, ws).length).toBeGreaterThan(0);
  });
});

describe("the console on real data", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); });

  it("opens every incident, its graph and its entity pane without an error", () => {
    const ws = WS[0];
    const states = new Map(ws.incidents.map(i => [i.id, foldIncidentState([], i)]));
    const errors: unknown[][] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((...a) => { errors.push(a); });
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    act(() => { root!.render(React.createElement(SentinelConsole, { workspace: ws, states, actions: fakeActions().actions, onRefresh: () => {}, ended: false })); });
    const click = (e: Element) => act(() => { (e as HTMLElement).click(); });
    const btn = (name: string) => [...el!.querySelectorAll("button")].filter(b => !b.closest("[hidden]")).find(b => (b.getAttribute("aria-label") ?? b.textContent ?? "").trim() === name) as HTMLButtonElement;
    const rows = () => [...el!.querySelectorAll('table[aria-label="Incidents"] tbody tr')];
    expect(rows()).toHaveLength(ws.incidents.length);
    for (let i = 0; i < ws.incidents.length; i++) {
      click(rows()[i]);
      click(btn("Open incident page"));
      expect(el!.querySelectorAll(".st-widget").length).toBe(4);
      click(btn("Investigate"));
      expect(el!.querySelectorAll("[data-node]").length).toBeGreaterThan(0);
      click(btn("Close investigation"));
      click(btn("Entities"));
      const first = el!.querySelector(".st-entities-list .xd-erow-main");
      if (first) click(first);
      click(btn("Close incident"));
    }
    expect(el!.textContent).not.toContain("—");
    spy.mockRestore();
    expect(errors).toEqual([]);
  });
});
