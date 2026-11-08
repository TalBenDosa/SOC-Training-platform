// The investigation console is XDR, this platform's own product (owner, 2026-11-08): it must not
// present itself as Microsoft Sentinel. Every screen of the console is rendered on a real XDR
// exercise and scanned, text and accessible names alike, for "Sentinel" naming this console.
// "SentinelOne" (an EDR vendor) and KQL table names such as SentinelHealth are data and pass.
// v4 (owner, 2026-11-08): the console does not use the portal's labels either (Activity log, Top
// insights, Threat management, Configuration, a Tables tab and the rest of PORTAL_LABELS).
import { describe, it, expect, afterEach, vi } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { SentinelConsole } from "./SentinelConsole";
import { fakeActions } from "./fixture";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import { stackForConsole } from "@/lib/team/investigationConsole";
import { buildWorkspace } from "@/lib/sentinel/workspace";
import { foldIncidentState } from "@/lib/sentinel/state";
import { XDR_PRODUCT, xdrText, xdrValue } from "@/lib/sentinel/xdrBrand";
import type { TelemetryEvent } from "@/lib/sim/types";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
vi.mock("next/navigation", () => ({ useRouter: () => ({ push() {}, replace() {}, back() {} }), usePathname: () => "/xdr", useSearchParams: () => new URLSearchParams() }));

/** "Sentinel" as a word of its own: not SentinelOne, SentinelHealth or microsoftSentinel. */
const NAMES_SENTINEL = /(?<![A-Za-z])Sentinel(?![A-Za-z])/;

/** The portal's own labels, as a whole text line or accessible name: XDR says these its own way. */
const PORTAL_LABELS = [
  "Activity log", "Incident activity log", "Close Incident activity log", "Activity logs content", "Top insights", "Similar incidents", "Incident timeline",
  "General", "Threat management", "Configuration", "Overview", "Logs", "Entity behavior", "Threat intelligence", "Analytics", "Automation", "Hunting",
  "Tables", "Queries", "Group by:", "Schema and Filter", "Example queries", "Run playbook", "Run playbook (Preview)", "View full details", "Incident actions",
  "Alert product names", "Evidence", "Last update time", "Creation time", "Similarity reason", "Display time (UTC+00:00)", "Active rules", "Active playbooks",
  "< Previous", "Next >", "Add to TI", "XDR | Incidents",
];

const ROSTER = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
function xdrExercise(company: string, seed: string) {
  const stack = stackForConsole({}, "sentinel");
  const events = buildTeamTimeline(company, "hard", seed, null, teamLoad("hard", ROSTER), stack)
    .filter(t => t.channel === "feed").map(t => t.body as unknown as TelemetryEvent);
  return { events, ws: buildWorkspace(events, { companyId: company, stack }) };
}

describe("xdrBrand", () => {
  it("renames the console and leaves the data model and other products alone", () => {
    expect(xdrText("Azure Sentinel")).toBe(XDR_PRODUCT);
    expect(xdrText("Microsoft Sentinel")).toBe(XDR_PRODUCT);
    expect(xdrText("ASI Scheduled Alerts")).toBe("XDR Scheduled Alerts");
    expect(xdrText('Sentinel raised "Port scan"')).toBe('XDR raised "Port scan"');
    expect(xdrText("A Microsoft Sentinel analytics rule raised this alert.")).toBe("An XDR analytics rule raised this alert.");
    expect(xdrText("Microsoft Sentinel raised a High alert at 02:09")).toBe("XDR raised a High alert at 02:09");
    for (const keep of ["SentinelOne", "SentinelOneThreats_CL", "SentinelHealth", "Microsoft Defender for Endpoint", "microsoftSentinel"]) expect(xdrText(keep)).toBe(keep);
  });

  it("copies on write and never mutates what it is given", () => {
    const raw = { ProductName: "Azure Sentinel", nested: { a: ["Microsoft Sentinel", 1] }, same: { b: "Okta" } };
    const out = xdrValue(raw);
    expect(raw.ProductName).toBe("Azure Sentinel");
    expect(out.ProductName).toBe(XDR_PRODUCT);
    expect(out.nested.a[0]).toBe(XDR_PRODUCT);
    expect(out.same).toBe(raw.same);
    const clean = { x: "Okta" };
    expect(xdrValue(clean)).toBe(clean);
  });
});

describe("an XDR exercise: the workspace", () => {
  const { events, ws } = xdrExercise("nexacorp", "xdr-naming-1");

  it("the feed does carry Sentinel-named SIEM rows, so the scan below has something to catch", () => {
    expect(events.some(e => NAMES_SENTINEL.test(JSON.stringify(e)))).toBe(true);
  });

  it("names its own analytics XDR Analytics and keeps the source products' real names", () => {
    const products = new Set(ws.alerts.map(a => a.product));
    expect(products).toContain(XDR_PRODUCT);
    for (const p of products) expect(p).not.toMatch(NAMES_SENTINEL);
    for (const row of ws.tables.SecurityIncident.rows) {
      expect(row.ProviderName).toBe("XDR");
      expect(String(row.IncidentUrl)).not.toMatch(/portal\.azure\.com/);
    }
    expect(ws.name).toMatch(/-xdr-prod$/);
  });

  it("no row of any table names the console Sentinel", () => {
    for (const [name, t] of Object.entries(ws.tables)) {
      for (const row of t.rows) expect(JSON.stringify(row), name).not.toMatch(NAMES_SENTINEL);
    }
  });
});

describe("an XDR exercise: every screen of the console", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); });

  /** What a person reads or hears: the text, and the names, titles and placeholders of controls. */
  function seen(): string {
    // One line per text node: textContent glues neighbours ("Microsoft Sentinel" + "IdentityInfo"),
    // which would hide a heading behind the word boundary the scan relies on.
    const parts: string[] = [];
    const walk = document.createTreeWalker(el!, NodeFilter.SHOW_TEXT);
    for (let n = walk.nextNode(); n; n = walk.nextNode()) if (n.textContent?.trim()) parts.push(n.textContent);
    for (const n of el!.querySelectorAll("[aria-label],[title],[placeholder],[alt]")) {
      for (const a of ["aria-label", "title", "placeholder", "alt"]) { const v = n.getAttribute(a); if (v) parts.push(v); }
    }
    return parts.join("\n");
  }
  function expectNoSentinel(where: string) {
    const lines = seen().split("\n");
    const hit = lines.find(l => NAMES_SENTINEL.test(l));
    expect(hit ? hit.slice(0, 200) : null, where).toBeNull();
    // The console's own chrome (controls, headings, labels and names), not the data it shows: a
    // department may well be called "General".
    const chrome: string[] = [];
    for (const n of el!.querySelectorAll("button, [role=tab], h1, h2, h3, h4, th, label, .st-nav-group, .xd-eyebrow, .st-field > .k, .st-k, .xd-psec-head, .st-results-status")) chrome.push((n.textContent ?? "").trim());
    for (const n of el!.querySelectorAll("[aria-label],[title],[placeholder]")) for (const a of ["aria-label", "title", "placeholder"]) { const v = n.getAttribute(a); if (v) chrome.push(v.trim()); }
    const label = chrome.find(l => PORTAL_LABELS.includes(l) || /^(Completed\.|Selected workspace|New Query \d)/.test(l));
    expect(label ?? null, `${where}: a portal label`).toBeNull();
    // no tab named Tables anywhere
    const tabs = [...el!.querySelectorAll("[role=tab]")].map(t => (t.textContent ?? "").trim());
    expect(tabs, where).not.toContain("Tables");
  }

  it("says XDR, never Sentinel", async () => {
    const { ws } = xdrExercise("nexacorp", "xdr-naming-1");
    const states = new Map(ws.incidents.map(i => [i.id, foldIncidentState([], i)]));
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    act(() => { root!.render(React.createElement(SentinelConsole, { workspace: ws, states, actions: fakeActions().actions, onRefresh: () => {}, ended: false, sessionKey: "s1" })); });
    const click = (e: Element) => act(() => { (e as HTMLElement).click(); });
    const btn = (name: string) => [...el!.querySelectorAll("button")].filter(b => !b.closest("[hidden]")).find(b => (b.getAttribute("aria-label") ?? b.textContent ?? "").trim() === name) as HTMLButtonElement;
    const navTo = (label: string) => click([...el!.querySelectorAll(".st-nav-item")].find(b => (b.textContent ?? "").startsWith(label))!);
    const settle = () => act(async () => { await new Promise(r => setTimeout(r, 8)); });

    expect(el!.querySelector(".st-topbar")!.textContent).toContain("XDR");
    for (const s of ["Incidents", "Query", "Hunts", "Search", "Entities", "Intel", "Home", "Detections", "Playbooks"]) {
      navTo(s);
      await settle();
      expectNoSentinel(s);
    }
    // The tables an analyst queries about alerts and incidents, with their product columns.
    navTo("Query");
    for (const q of ["SecurityAlert | take 200", "SecurityIncident | take 50"]) {
      const ed = el!.querySelector<HTMLTextAreaElement>("[data-testid=kql-input]")!;
      act(() => {
        Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(ed, q);
        ed.dispatchEvent(new Event("input", { bubbles: true }));
      });
      click(btn("Run"));
      await settle();
      expect(el!.querySelectorAll("table[role=grid] tbody tr[data-row]").length, q).toBeGreaterThan(0);
      expectNoSentinel(q);
    }
    navTo("Incidents");
    const rows = () => [...el!.querySelectorAll('table[aria-label="Incidents"] tbody tr')];
    expect(rows().length).toBeGreaterThan(0);
    for (let i = 0; i < rows().length; i++) {
      click(rows()[i]);
      expectNoSentinel(`incident ${i} preview`);
      click(btn("Open incident page"));
      expectNoSentinel(`incident ${i}`);
      click(btn("Case history"));
      expectNoSentinel(`incident ${i} case history`);
      click(btn("Close Case history"));
      click(btn("Investigate"));
      expectNoSentinel(`incident ${i} graph`);
      click(btn("Close investigation"));
      click(btn("Entities"));
      const first = el!.querySelector(".st-entities-list .xd-erow-main");
      if (first) click(first);
      expectNoSentinel(`incident ${i} entities`);
      click(btn("Close incident"));
    }
  });
});
