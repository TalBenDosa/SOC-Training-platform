// The team room of an XDR session (config value "sentinel") names its console XDR (owner,
// 2026-11-08): the investigate buttons, the tours, the role guide, the activity log, the report
// and the Session Builder choice. Rendered text and accessible names are scanned for "Sentinel".
import { describe, it, expect, afterEach, vi } from "vitest";
import React, { act } from "react";
import fs from "node:fs";
import path from "node:path";
import { createRoot, type Root } from "react-dom/client";
import { T2Console } from "./T2Console";
import { HuntConsole } from "./HuntConsole";
import { RoleGuideModal } from "./RoleGuideModal";
import { ActivityLog } from "./ActivityLog";
import { TeamReport } from "./TeamReport";
import { forSentinel, tourFor } from "./teamTours";
import { escalationStates } from "@/lib/team/projections";
import { computeReport } from "@/lib/team/report/computeReport";
import { CONSOLE_CHOICES } from "@/lib/team/investigationConsole";
import { nameOf, sampleEvents } from "@/lib/team/__fixtures__/handoffEvents";
import type { Ev, RosterMember } from "@/lib/team/types";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

/** "Sentinel" as a word of its own: not SentinelOne, not an identifier. */
const NAMES_SENTINEL = /(?<![A-Za-z])Sentinel(?![A-Za-z])/;

let root: Root | null = null; let el: HTMLDivElement | null = null;
afterEach(() => { act(() => root?.unmount()); el?.remove(); root = null; el = null; vi.unstubAllGlobals(); });
async function mount(node: React.ReactElement) {
  el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
  await act(async () => root!.render(node));
  await act(async () => { await new Promise(r => setTimeout(r, 0)); });
  return el;
}
function seen(): string {
  const parts = [el!.textContent ?? ""];
  for (const n of el!.querySelectorAll("[aria-label],[title],[placeholder]")) for (const a of ["aria-label", "title", "placeholder"]) { const v = n.getAttribute(a); if (v) parts.push(v); }
  return parts.join("\n");
}

describe("XDR session: the team room", () => {
  it("the Tier-2 header says Investigate in XDR", async () => {
    const events = sampleEvents().slice(0, 7);
    await mount(React.createElement(T2Console, {
      sessionId: "s1", role: "t2", meId: "u2", events, escalations: [events[3]], escState: escalationStates(events), reportedIds: new Set(), reportByEid: new Map(), elevatedIds: new Set(),
      containments: [], scope: null, scopes: new Map(), incidents: [], incidentOf: new Map(), nameOf, act: async () => true, actR: async () => ({ ok: true, code: null }),
      consoleName: "XDR", onEdr: () => {},
    } as never));
    expect(el!.querySelector("[data-investigate-header]")!.textContent).toContain("Investigate in XDR");
    expect(seen()).not.toMatch(NAMES_SENTINEL);
  });

  it("the Tier-3 hunt console says Investigate in XDR", async () => {
    await mount(React.createElement(HuntConsole, { events: sampleEvents(), sessionId: "s1", consoleName: "XDR", onEdr: () => {}, act: async () => true, nameOf, scope: null, elevations: [], elevAcked: new Set() } as never));
    expect(el!.textContent).toContain("Investigate in XDR");
    expect(seen()).not.toMatch(NAMES_SENTINEL);
  });

  it("every role's tour and guide name XDR", async () => {
    for (const role of ["t1", "t2", "t3", "mgr", "lead", "de", "ti", "instructor"]) {
      const tour = tourFor(role, () => {});
      if (tour) {
        const steps = forSentinel(tour.steps);
        expect(JSON.stringify(steps), role).not.toMatch(NAMES_SENTINEL);
        const edr = steps.find(s => s.target === "edr-button");
        if (edr) expect(edr.title, role).toBe("Investigate in XDR");
      }
      await mount(React.createElement(RoleGuideModal, { role, onClose: () => {}, isSentinel: true }));
      expect(seen(), role).not.toMatch(NAMES_SENTINEL);
      expect(el!.textContent, role).not.toContain("Investigate in EDR");
      act(() => root?.unmount()); el?.remove(); root = null; el = null;
    }
  });

  it("the activity log says XDR", async () => {
    const ev = (seq: number, type: string, payload: Record<string, unknown>): Ev => ({ seq, type, actor_id: "u2", role: "t2", payload, occurred_at: "2026-11-08T10:00:00.000Z" });
    await mount(React.createElement(ActivityLog, { activity: [ev(1, "sentinel.incident_updated", { patch: { status: "Closed" } }), ev(2, "sentinel.incident_updated", { patch: { owner: "Noa" } }), ev(3, "sentinel.bookmark_added", { name: "Beacon" })], nameOf }));
    expect(el!.textContent).toContain("set an XDR incident to Closed");
    expect(el!.textContent).toContain("bookmarked XDR results");
    expect(seen()).not.toMatch(NAMES_SENTINEL);
  });

  it("the shift report heads the console's line XDR", async () => {
    const roster: RosterMember[] = [{ user_id: "a", role: "t2", status: "ready", name: "Dana", handle: null }];
    const events: Ev[] = [
      { seq: 1, type: "session.started", actor_id: null, role: null, payload: {}, occurred_at: "2026-11-08T10:00:00.000Z" },
      { seq: 2, type: "sentinel.query_run", actor_id: "a", role: "t2", payload: { ok: true }, occurred_at: "2026-11-08T10:01:00.000Z" },
      { seq: 3, type: "session.ended", actor_id: null, role: null, payload: {}, occurred_at: "2026-11-08T10:30:00.000Z" },
    ];
    const report = computeReport(events, roster);
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, json: async () => ({ team: report.team, perUser: report.perUser, answers: {}, seesAll: true }) })));
    await mount(React.createElement(TeamReport, { sessionId: "s1", events, roster, me: { id: "x", is_staff: true, role: "instructor" } }));
    expect(el!.textContent).toContain("XDR");
    expect(el!.textContent).toContain("1/1 queries");
    expect(seen()).not.toMatch(NAMES_SENTINEL);
  });

  it("the Session Builder offers an XDR console that is not presented as Microsoft's or Azure's", () => {
    const xdr = CONSOLE_CHOICES.find(c => c.id === "sentinel")!;
    expect(xdr.label).toBe("XDR console (KQL)");
    expect(xdr.hint).toMatch(/Microsoft 365, Defender and identity telemetry/);
    expect(xdr.hint).toMatch(/KQL/);
    for (const c of CONSOLE_CHOICES) expect(`${c.label} ${c.hint}`).not.toMatch(/Sentinel|Azure|Microsoft's/);
  });

  it("no string the team room pages show names Sentinel (source scan of what cannot be mounted alone)", () => {
    // The room page and the Session Builder are too large to mount here: their string literals and
    // JSX text are scanned instead, comments and identifiers left out.
    const root = path.join(__dirname, "..", "..");
    for (const f of [path.join(__dirname, "..", "page.tsx"), path.join(root, "page.tsx"), path.join(__dirname, "RoleGuideModal.tsx"), path.join(__dirname, "teamTours.ts")]) {
      const src = fs.readFileSync(f, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1").replace(/\{\/\*[\s\S]*?\*\/\}/g, "");
      const hits = src.split("\n").filter(l => NAMES_SENTINEL.test(l));
      expect(hits, f).toEqual([]);
    }
  });
});
