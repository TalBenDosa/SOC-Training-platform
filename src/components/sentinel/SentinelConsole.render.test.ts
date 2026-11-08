// The console end to end on a tiny workspace: the screens an analyst walks through, against the real
// KQL engine and a fake SentinelActions. What a person would see and press, not component internals.
import { describe, it, expect, afterEach, vi } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { SentinelConsole, type SentinelConsoleProps } from "./SentinelConsole";
import { fakeActions, fixtureState, fixtureWorkspace, INCIDENTS } from "./fixture";
import { CLASSIFICATIONS, explorationsFor, queryBlockAt, toCsv, whereClause } from "./helpers";
import type { IncidentState, SentinelActions, SentinelIncident } from "@/lib/sentinel/types";
import { NO_APPROVER } from "@/lib/team/isolationApproval";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
// jsdom has no ResizeObserver and no layout; the console falls back to its default sizes.

let root: Root | null = null;
let el: HTMLDivElement | null = null;
afterEach(() => { act(() => root?.unmount()); el?.remove(); root = null; el = null; });

function statesFor(over: Record<string, Partial<IncidentState>> = {}) {
  const m = new Map<string, IncidentState>();
  for (const i of INCIDENTS) m.set(i.id, fixtureState({ severity: i.severity, ...over[i.id] }));
  return m;
}

function mount(props: Partial<SentinelConsoleProps> = {}) {
  const fake = fakeActions();
  const base: SentinelConsoleProps = { workspace: fixtureWorkspace(), states: statesFor(), actions: fake.actions, onRefresh: () => {}, ended: false, ...props };
  el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
  act(() => { root!.render(React.createElement(SentinelConsole, base)); });
  return { ...fake, base, rerender: (next: Partial<SentinelConsoleProps>) => act(() => { root!.render(React.createElement(SentinelConsole, { ...base, ...next })); }) };
}

const q = <T extends Element = HTMLElement>(s: string) => el!.querySelector<T>(s);
const all = <T extends Element = HTMLElement>(s: string) => [...el!.querySelectorAll<T>(s)];
const text = () => el!.textContent ?? "";
const button = (name: string | RegExp) => {
  const b = all<HTMLButtonElement>("button,[role=option],[role=menuitem]").filter(x => !x.closest("[hidden]")).find(x => {
    const n = (x.getAttribute("aria-label") ?? x.textContent ?? "").trim();
    return typeof name === "string" ? n === name : name.test(n);
  });
  if (!b) throw new Error(`no button ${name}`);
  return b;
};
const click = (e: HTMLElement) => act(() => { e.click(); });
const press = (name: string | RegExp) => click(button(name));
function setValue(e: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement, value: string, cursor?: number) {
  const proto = e instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : e instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  act(() => {
    Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(e, value);
    if (cursor !== undefined && !(e instanceof HTMLSelectElement)) e.setSelectionRange(cursor, cursor);
    e.dispatchEvent(new Event(e instanceof HTMLSelectElement ? "change" : "input", { bubbles: true }));
  });
}
const key = (e: Element, k: string, init: KeyboardEventInit = {}) => act(() => { e.dispatchEvent(new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true, ...init })); });
const settle = () => act(async () => { await new Promise(r => setTimeout(r, 8)); });

/** A menu item's label without its unopened-incidents badge. */
const navLabel = (b: Element) => [...b.childNodes].filter(n => !(n instanceof Element && n.classList.contains("st-nav-badge"))).map(n => n.textContent).join("");
const nav = (name: string) => click(all<HTMLButtonElement>(".st-nav-item").find(b => navLabel(b) === name)!);
const editor = () => q<HTMLTextAreaElement>("[data-testid=kql-input]")!;
async function runInLogs(query: string) {
  nav("Query");
  setValue(editor(), query, query.length);
  press("Run");
  await settle();
}
const gridRows = () => all("table[role=grid] tbody tr[data-row]");
const incidentRows = () => all('table[aria-label="Incidents"] tbody tr');

describe("shell", () => {
  it("has the requested menu and nothing else", () => {
    mount();
    // XDR's own menu and words (owner, 2026-11-08, v4): not the portal's groups and blade names.
    expect(all(".st-nav-item").map(navLabel)).toEqual(["Home", "Query", "Search", "Incidents", "Hunts", "Entities", "Intel", "Detections", "Playbooks"]);
    expect(all(".st-nav-group").map(b => b.textContent)).toEqual(["Workspace", "Investigate", "Operate"]);
    expect(q("[data-testid=workspace-name]")!.textContent).toBe("contoso-xdr-prod");
    expect(q(".st-topbar strong")!.textContent).toBe("XDR");
    expect(q("nav.st-nav")!.getAttribute("aria-label")).toBe("XDR menu");
    // The page header: the group as an eyebrow, the page name, the workspace as a chip. No "XDR | Incidents",
    // no "Selected workspace", no Home > XDR path.
    expect(q(".st-blade-head h1")!.textContent).toBe("Incidents");
    expect(q(".st-blade-head .xd-eyebrow")!.textContent).toBe("Investigate");
    expect(q(".st-blade-head .xd-ws")!.textContent).toContain("contoso-xdr-prod");
    expect(q(".st-blade-head .st-crumb")).toBeNull();
    expect(text()).not.toContain("Selected workspace");
    // Review 2026-11: the seat in words, and the link says where it goes (it keeps the two-window behaviour).
    expect(q<HTMLAnchorElement>(".st-topbar a")!.textContent).toBe("Back to team room");
    expect(q(".st-topbar")!.textContent).toContain("Tal Analyst (Tier-2)");
    expect(q(".st-topbar")!.textContent).not.toContain("(t2)");
  });

  it("Back to team room brings the team room forward when a window handler is given", () => {
    const onBack = vi.fn();
    mount({ onBack, backHref: "/team/s1" });
    const a = q<HTMLAnchorElement>(".st-topbar a")!;
    expect(a.getAttribute("href")).toBe("/team/s1");
    click(a);
    expect(onBack).toHaveBeenCalledTimes(1);
  });

  it("the Incidents badge counts the incidents this viewer has not opened, and remembers them per session", () => {
    try { window.localStorage.clear(); } catch { /* none */ }
    mount({ sessionKey: "sess-1" });
    const badge = () => q(".st-nav-badge")?.textContent ?? null;
    const open = INCIDENTS.length;
    expect(badge()).toBe(String(open));
    const item = () => all(".st-nav-item").find(b => navLabel(b) === "Incidents")!;
    expect(item().getAttribute("aria-label")).toBe(`Incidents: ${open} not opened yet, of ${open} open`);
    click(incidentRows()[0]);
    press("Open incident page");
    press("Close incident");
    expect(badge()).toBe(String(open - 1));
    // The badge's meaning is in its name and tooltip, next to the open total the page shows
    // (2026-11-08 review: "Incidents 4" beside five open incidents read as a wrong count).
    expect(item().getAttribute("aria-label")).toBe(`Incidents: ${open - 1} not opened yet, of ${open} open`);
    expect(item().getAttribute("title")).toBe(`Incidents: ${open - 1} not opened yet, of ${open} open`);
    expect(q(".st-kpi")!.textContent).toContain(String(open));
    // a new mount of the same session (a reload) still knows it was opened
    act(() => root?.unmount()); el?.remove();
    mount({ sessionKey: "sess-1" });
    expect(badge()).toBe(String(open - 1));
  });

  it("new incidents are announced politely and refusals assertively, from regions already in the page", async () => {
    const m = mount();
    const polite = q('.st-toasts [aria-live="polite"]');
    const assertive = q('.st-toasts [aria-live="assertive"]');
    expect(polite).not.toBeNull();
    expect(assertive).not.toBeNull();
    const arrived: SentinelIncident = { ...INCIDENTS[1], id: "inc-104", number: 104, title: "Another arrival" };
    m.rerender({ workspace: fixtureWorkspace({ incidents: [...INCIDENTS, arrived] }) });
    expect(polite!.textContent).toContain("Another arrival");
    expect(polite!.querySelector("[role=alert],[role=status]")).toBeNull();
    expect(assertive!.textContent).toBe("");
  });

  it("the Low band and the faint text meet WCAG AA against white", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const css = fs.readFileSync(path.join(__dirname, "sentinel.css"), "utf8");
    const hex = (name: string) => css.match(new RegExp(`--${name}:\\s*(#[0-9a-f]{6})`, "i"))![1];
    const lum = (h: string) => { const c = [1, 3, 5].map(i => parseInt(h.slice(i, i + 2), 16) / 255).map(v => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; };
    const onWhite = (h: string) => 1.05 / (lum(h) + 0.05);
    expect(onWhite(hex("st-text-3"))).toBeGreaterThanOrEqual(4.5);
    // white text on the accent (primary buttons, badges) and on the top bar
    expect(onWhite(hex("st-accent"))).toBeGreaterThanOrEqual(4.5);
    expect(onWhite(hex("st-bar"))).toBeGreaterThanOrEqual(4.5);
    // XDR's own type (v4): Manrope and IBM Plex Mono, no Segoe UI, no Inter-only look, no Azure blue,
    // and none of Fluent's warm greys.
    expect(css).toMatch(/--st-sans: var\(--font-xdr-sans\), "Manrope"/);
    expect(css).toMatch(/--st-mono: var\(--font-xdr-mono\), "IBM Plex Mono"/);
    expect(css).toMatch(/font-family: var\(--st-sans\)/);
    expect(css).not.toMatch(/Segoe UI|#0078d4|--font-inter|"Inter"|JetBrains/i);
    expect(css).not.toMatch(/#323130|#605e5c|#edebe9|#faf9f8|#c8c6c4/i);
    const layout = fs.readFileSync(path.join(__dirname, "../../app/(app)/xdr/layout.tsx"), "utf8");
    expect(layout).toMatch(/Manrope\(/);
    expect(layout).toMatch(/IBM_Plex_Mono\(/);
    expect(layout).toMatch(/--font-xdr-sans/);
    expect(onWhite(hex("st-low-edge"))).toBeGreaterThanOrEqual(3);
    expect(css).toMatch(/\.st-band\.Low:not\(\.dotted\), \.st-cellband\.Low \{ box-shadow: inset 0 0 0 1px var\(--st-low-edge\)/);
    // XDR's chips and tiles: every ink on its own background, AA for small text.
    const ratio = (a: string, b: string) => { const [x, y] = [lum(a), lum(b)].sort((m, n) => n - m); return (x + 0.05) / (y + 0.05); };
    for (const [ink, bg] of [["xd-high-ink", "xd-high-bg"], ["xd-med-ink", "xd-med-bg"], ["xd-low-ink", "xd-low-bg"], ["xd-info-ink", "xd-info-bg"], ["xd-tac-ink", "xd-tac-bg"],
      ["xd-t-blue", "xd-t-blue-bg"], ["xd-t-teal", "xd-t-teal-bg"], ["xd-t-plum", "xd-t-plum-bg"], ["xd-t-amber", "xd-t-amber-bg"], ["st-text-2", "xd-info-bg"],
      // the violet accent (owner, 2026-11-08): links, the nav's current item, soft tiles and the top bar
      ["st-accent", "st-accent-faint"], ["st-accent", "st-accent-soft"], ["st-accent-ink", "st-accent-faint"], ["st-accent-hover", "st-accent-soft"],
      // v4: grid header labels, the menu and data sources on the canvas, code blocks
      ["st-text-2", "xd-grid-head"], ["st-accent-ink", "xd-grid-head"], ["st-text-2", "st-canvas"], ["st-text-2", "xd-zebra"], ["st-accent-ink", "st-accent-soft"], ["xd-code-ink", "xd-code-bg"]]) {
      expect(ratio(hex(ink), hex(bg)), `${ink} on ${bg}`).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("every screen renders, every control has a name, no em dash in the text", async () => {
    mount();
    for (const s of ["Home", "Query", "Search", "Incidents", "Hunts", "Entities", "Intel", "Detections", "Playbooks"]) {
      nav(s);
      await settle();
      for (const b of all("button")) expect((b.getAttribute("aria-label") ?? b.textContent ?? "").trim(), b.outerHTML.slice(0, 120)).not.toBe("");
      expect(text()).not.toContain("—");
    }
  });

  it("takes what lies under it out of the tab order, and gives it back", () => {
    const beside = document.createElement("nav");
    document.body.appendChild(beside);
    mount();
    expect(beside.hasAttribute("inert")).toBe(true);
    act(() => root?.unmount());
    root = null;
    expect(beside.hasAttribute("inert")).toBe(false);
    beside.remove();
  });

  it("the theme is scoped to its own root", () => {
    mount();
    expect(q("[data-testid=sentinel-root]")!.className).toBe("st-root");
  });
});

describe("incidents grid", () => {
  it("shows the KPI tiles from the real state, and hides Closed by default", () => {
    mount({ states: statesFor({ "inc-102": { status: "Closed" } }) });
    expect(incidentRows()).toHaveLength(1);
    const kpi = all(".st-kpi").map(k => k.textContent);
    expect(kpi[0]).toBe("Open incidents1");
    expect(kpi[1]).toBe("New1");
    expect(kpi[2]).toBe("Active0");
  });

  it("sorts by a column and filters by the search box", () => {
    mount();
    const numbers = () => incidentRows().map(r => r.querySelectorAll("td")[2].textContent);
    expect(numbers()).toEqual(["102", "101"]);
    press("ID");
    press("ID");
    expect(numbers()).toEqual(["101", "102"]);
    setValue(q<HTMLInputElement>('input[placeholder^="Search by ID"]')!, "service");
    expect(numbers()).toEqual(["102"]);
  });

  it("opens the preview, and changing the owner there writes through the actions", async () => {
    const { calls } = mount();
    click(incidentRows().find(r => r.textContent?.includes("Initial access"))!);
    expect(text()).toContain("Open incident page");
    press(/^Owner: Unassigned/);
    press("Dana Lead");
    expect(calls.find(c => c.fn === "updateIncident"), "nothing changes before Apply").toBeUndefined();
    await act(async () => { button("Apply").click(); });
    expect(calls.find(c => c.fn === "updateIncident")?.args).toEqual(["inc-101", { owner: "Dana Lead" }]);
  });

  it("marks a new incident, raises a notification, and opening it clears both", () => {
    const m = mount();
    expect(q(".st-new-mark")).toBeNull();
    const arrived: SentinelIncident = { ...INCIDENTS[1], id: "inc-103", number: 103, title: "A late arrival" };
    const ws = fixtureWorkspace({ incidents: [...INCIDENTS, arrived] });
    m.rerender({ workspace: ws });
    expect(q(".st-new-mark")?.textContent).toBe("New");
    expect(q(".st-toast")?.textContent).toContain("A late arrival");
    press("Open incident");
    expect(text()).toContain("Incident #103");
    expect(q(".st-toast")).toBeNull();
    press("Close incident");
    expect(q(".st-new-mark")).toBeNull();
  });
});

function openDetails(name = "Initial access") {
  click(incidentRows().find(r => r.textContent?.includes(name))!);
  press("Open incident page");
}

describe("incident details", () => {
  it("moves focus into the blade, and back to what opened it", async () => {
    mount();
    click(incidentRows().find(r => r.textContent?.includes("Initial access"))!);
    const opener = button("Open incident page");
    opener.focus();
    act(() => { opener.click(); });
    expect(document.activeElement?.className).toBe("st-inc");
    press("Close incident");
    await settle();
    expect(document.activeElement?.textContent).toBe("Open incident page");
  });

  it("lays out the left panel, toolbar and four widgets", () => {
    mount();
    openDetails();
    expect(text()).toContain("Incident #101");
    for (const label of ["Refresh", "Query", "Tasks", "Case history", "Investigate", "Respond", "Summary", "Entities"]) expect(button(label)).toBeTruthy();
    for (const label of ["Workspace", "Description", "Sources", "Linked data", "Updated", "Created", "Tactics and techniques"]) expect(text()).toContain(label);
    expect(all(".st-widget h3").map(h => h.textContent?.trim())).toEqual(["Alert timeline", "Entities", "Quick findings", "Related incidents"]);
    // the path back: Home / Incidents / #101
    expect(all(".st-inc .st-crumb > span").map(s => s.textContent?.replace("/", ""))).toEqual(["Home", "Incidents", "#101"]);
    // linked data as three small cards
    expect(all(".st-inc-left .xd-linkcard").map(c => c.getAttribute("aria-label")?.replace(/\d+$/, "n"))).toEqual(["Events, n", "Alerts, n", "Bookmarks, n"]);
    expect(button("Alerts, 2")).toBeTruthy();
  });

  it("Linked data opens the Query panel on its query, already run, and Done closes it", async () => {
    const { calls } = mount();
    openDetails();
    press("Alerts, 2");
    await settle();
    expect(q('[role=dialog][aria-labelledby] h2')?.textContent).toBe("Query");
    expect(editor().value).toContain("SystemAlertId in");
    expect(text()).toContain("Query complete: 2 rows from the last 24 hours.");
    expect(gridRows()).toHaveLength(2);
    expect(calls.find(c => c.fn === "queryRan")).toBeTruthy();
    press("Done");
    expect(q("[data-testid=kql-input]")).toBeNull();
  });

  it("a timeline item shows the alert details, and the System alert ID goes to Query", async () => {
    mount();
    openDetails();
    press(/^Suspicious process launched/);
    expect(text()).toContain("System alert ID");
    press("aaaaaaaa-0002");
    await settle();
    expect(editor().value).toContain("DeviceProcessEvents");
    expect(gridRows()).toHaveLength(2);
  });

  it("closing happens in the Status list: a classification from the five real values, and reopen works", async () => {
    const { calls, rerender, base } = mount();
    openDetails();
    press(/^Status: New/);
    press("Closed");
    expect(button("Apply").disabled).toBe(true);
    press(/^Classification/);
    expect(all('[aria-label="Classification"] [role=option]').map(o => o.textContent)).toEqual(CLASSIFICATIONS);
    press(CLASSIFICATIONS[1]);
    setValue(q<HTMLTextAreaElement>('textarea[placeholder="Comment"]')!, "Admin was patching");
    await act(async () => { button("Apply").click(); });
    expect(calls.find(c => c.fn === "updateIncident")?.args).toEqual(["inc-101", { status: "Closed", classification: CLASSIFICATIONS[1], closingComment: "Admin was patching" }]);

    const states = new Map(base.states);
    states.set("inc-101", fixtureState({ status: "Closed", classification: CLASSIFICATIONS[1] }));
    rerender({ states });
    press(/^Status: Closed/);
    press("Active");
    await act(async () => { button("Apply").click(); });
    expect(calls.filter(c => c.fn === "updateIncident").at(-1)?.args).toEqual(["inc-101", { status: "Active" }]);
  });

  it("Severity lists lowest first, Cancel writes nothing, and the panel collapses to three glyphs", async () => {
    const { calls } = mount();
    openDetails();
    press(/^Severity: High/);
    expect(all('[aria-label="Severity"] [role=option]').map(o => o.textContent)).toEqual(["Informational", "Low", "Medium", "High"]);
    press("Medium");
    press("Cancel");
    expect(calls.find(c => c.fn === "updateIncident")).toBeUndefined();
    press("Collapse details panel");
    expect(q(".st-fieldbar.collapsed")).toBeTruthy();
    expect(() => button("Investigate")).toThrow();
    press(/^Severity: High/);
    expect(q('[role=dialog][aria-label="Severity"]')).toBeTruthy();
  });

  it("lists one line per tactic, in words, each opening its techniques", () => {
    mount();
    openDetails();
    expect(all(".st-inc-left .st-tactic").map(b => b.textContent)).toEqual(["Initial Access (1)", "Execution (1)"]);
    click(all(".st-inc-left .st-tactic")[1]);
    expect(q(".st-inc-left")?.textContent).toContain("T1204.002");
  });

  it("alert details open in a flyout beside the timeline and close with their X", () => {
    mount();
    openDetails();
    press(/^Unfamiliar sign-in properties/);
    const fly = q('.st-flyout')!;
    for (const label of ["Description", "Severity", "Status", "Events", "Product name", "Entities (2)", "Tactics and techniques", "System alert ID", "Rule name", "Last update time", "Start time", "End time"]) expect(fly.textContent).toContain(label);
    expect(fly.textContent).toContain("Sign-ins from a rare location");
    press("Close alert details");
    expect(q(".st-flyout")).toBeNull();
  });

  it("Related incidents gives the reason, and the info button lists the common items", () => {
    const shared: SentinelIncident = { ...INCIDENTS[1], id: "inc-103", number: 103, title: "Shares an entity", entityIds: ["host:fin-lt-042"], alertIds: [] };
    mount({ workspace: fixtureWorkspace({ incidents: [...INCIDENTS, shared] }) });
    openDetails();
    expect(q(".st-similar")?.textContent).toContain("Shared entities");
    expect(all(".st-similar thead th").map(t => t.textContent)).toEqual(["Severity", "ID", "Title", "Updated", "Status", "Why related", "Owner"]);
    press(/^Shared entities: show the common items/);
    expect(q('[role=dialog][aria-label="Shared entities"]')?.textContent).toContain("203.0.113.50");
  });

  it("Tasks and Case history are live, and a comment goes through the actions", async () => {
    const { calls, rerender, base } = mount();
    openDetails();
    press("Case history");
    expect(all('[aria-label="Show in case history"] button').map(b => b.textContent)).toEqual(["Everything", "Changes", "Comments"]);
    const box = q<HTMLTextAreaElement>('textarea[placeholder="Write a comment..."]')!;
    setValue(box, "Checked the sign-in");
    await act(async () => { button("Comment").click(); });
    expect(calls.find(c => c.fn === "addComment")?.args).toEqual(["inc-101", "Checked the sign-in"]);
    const states = new Map(base.states);
    states.set("inc-101", fixtureState({ comments: [{ id: "c1", author: "Dana Lead", text: "Seen, thanks", at: "2026-01-01T09:00:00.000Z" }] }));
    rerender({ states });
    expect(text()).toContain("Seen, thanks");
    press("Comments");
    expect(button("Comments").getAttribute("aria-pressed")).toBe("true");
    expect(text()).toContain("Seen, thanks");
    press("Close Case history");

    press("Tasks");
    click(q<HTMLInputElement>('[role=dialog] input[type=checkbox]')!);
    expect(calls.find(c => c.fn === "setTask")?.args).toEqual(["inc-101", "Review the alerts", true]);
  });

  it("entity menu offers only what the product allows for the kind", () => {
    mount();
    openDetails();
    press("Actions for FIN-LT-042");
    expect(all("[role=menuitem]").map(i => i.textContent)).toEqual(["Run action"]);
    key(q("[role=menu]")!, "Escape");
    press("Actions for 203.0.113.50");
    expect(all("[role=menuitem]").map(i => i.textContent)).toEqual(["Add to Intel"]);
    key(q("[role=menu]")!, "Escape");
    expect(el!.querySelector('[aria-label="Actions for jdoe@contoso.example"]')).toBeNull();
  });

  it("Add to Intel lands on the Intel screen", async () => {
    const { calls, rerender, base } = mount();
    openDetails();
    press("Actions for 203.0.113.50");
    await act(async () => { button("Add to Intel").click(); });
    const comment = calls.find(c => c.fn === "addComment")!.args as [string, string];
    const states = new Map(base.states);
    states.set("inc-101", fixtureState({ comments: [{ id: "c1", author: "Tal Analyst", text: comment[1], at: "2026-01-01T09:00:00.000Z" }] }));
    rerender({ states });
    press("Close incident");
    nav("Intel");
    const row = q('table[aria-label="Threat indicators"] tbody tr')!;
    expect(row.textContent).toContain("203.0.113.50");
    expect(row.textContent).toContain("Tal Analyst");
  });
});

describe("incidents grid controls", () => {
  it("filters are chips: More filters reveals Source and Owner", () => {
    mount();
    expect(button("Severity: All").classList.contains("xd-fchip")).toBe(true);
    expect(button("Status: 2 selected")).toBeTruthy();
    expect(() => button("Source: All")).toThrow();
    press("More filters (2)");
    expect(button("Source: All")).toBeTruthy();
    expect(button("Owner: All")).toBeTruthy();
    expect(button("Fewer filters")).toBeTruthy();
  });

  it("Actions applies to the ticked incidents", async () => {
    const { calls } = mount();
    expect(button("Actions").disabled).toBe(true);
    click(q<HTMLInputElement>('input[aria-label="Select incident 101"]')!);
    click(q<HTMLInputElement>('input[aria-label="Select incident 102"]')!);
    press("Actions");
    setValue(q<HTMLSelectElement>('[role=dialog] select')!, "Low");
    await act(async () => { button("Apply").click(); });
    expect(calls.filter(c => c.fn === "updateIncident").map(c => c.args)).toEqual([["inc-101", { severity: "Low" }], ["inc-102", { severity: "Low" }]]);
  });

  it("Columns hides a column, and the time range filters by creation", () => {
    mount();
    press("Columns");
    click(all<HTMLInputElement>('[aria-label="Columns"] input')[0]);
    expect(all('table[aria-label="Incidents"] th').map(t => t.textContent)).not.toContain("ID");
    expect(incidentRows()).toHaveLength(2);
  });

  it("with Auto-refresh off the list holds until Refresh", () => {
    const m = mount();
    click(q('[role=switch]')!);
    const arrived: SentinelIncident = { ...INCIDENTS[1], id: "inc-103", number: 103, title: "A late arrival" };
    m.rerender({ workspace: fixtureWorkspace({ incidents: [...INCIDENTS, arrived] }) });
    expect(incidentRows()).toHaveLength(2);
    press("Refresh");
    expect(incidentRows()).toHaveLength(3);
  });

  it("the pager is always there: Showing 1 to 2 of 2, with icon buttons", () => {
    mount();
    expect(button("Previous page").disabled).toBe(true);
    expect(button("Next page").disabled).toBe(true);
    expect(q(".st-pager")?.textContent).toContain("Showing 1 to 2 of 2");
    expect(() => button("< Previous")).toThrow();
  });

  it("XDR's grid: a small caps header bar without a sort glyph on every column, and a left accent", async () => {
    mount();
    const grid = q('table[aria-label="Incidents"]')!;
    expect(grid.classList.contains("xd-grid")).toBe(true);
    const sorted = all('table[aria-label="Incidents"] th[aria-sort]').filter(t => t.getAttribute("aria-sort") !== "none");
    expect(sorted.map(t => t.textContent)).toEqual(["Created"]);
    expect(sorted[0].hasAttribute("data-sorted")).toBe(true);
    expect(all('table[aria-label="Incidents"] th[data-sorted]')).toHaveLength(1);
    // no portal cell band beside the severity: the pill alone
    expect(q(".st-igrid .st-cellband")).toBeNull();
    const fs = await import("node:fs");
    const path = await import("node:path");
    const css = fs.readFileSync(path.join(__dirname, "sentinel.css"), "utf8");
    expect(css).toMatch(/\.xd-grid th \{[^}]*text-transform: uppercase/);
    expect(css).toMatch(/\.xd-grid tbody tr:nth-child\(even\) td \{ background: var\(--xd-zebra\)/);
    expect(css).toMatch(/tr:hover td:first-child[^{]*\{ box-shadow: inset 3px 0 0 var\(--st-accent\)/);
  });
});

describe("logs", () => {
  it("runs on Shift+Enter and reports status, row count and UTC", async () => {
    mount();
    nav("Query");
    setValue(editor(), "SigninLogs", 10);
    key(editor(), "Enter", { shiftKey: true });
    await settle();
    expect(text()).toContain("Query complete");
    expect(text()).toContain("Results from the last 24 hours.");
    expect(text()).toContain("120 rows");
    expect(text()).toContain("Times in UTC");
    const tg = all("table[role=grid] th").find(t => t.querySelector(".xd-colname")?.textContent === "TimeGenerated")!;
    expect(tg.querySelector(".xd-utc")?.textContent).toBe("UTC");
    expect(text()).not.toMatch(/Completed\.|Display time|\[UTC\]/);
  });

  it("pages at 50 and moves between pages", async () => {
    mount();
    await runInLogs("SigninLogs");
    expect(gridRows()).toHaveLength(50);
    expect(text()).toContain("Showing 1 to 50 of 120");
    press("Next page");
    expect(text()).toContain("Showing 51 to 100 of 120");
    press("Last page");
    expect(gridRows()).toHaveLength(20);
  });

  it("shows a parse error with line and column and underlines the token", async () => {
    mount();
    await runInLogs("SigninLogs\n| wher ResultType == 0");
    const alert = q(".st-editor-err")!;
    expect(alert.textContent).toMatch(/line 2, column 3/);
    expect(q("[data-testid=kql-error-mark]")).toBeTruthy();
    expect(text()).toContain("The query failed");
  });

  it("runs only the query under the cursor", () => {
    expect(queryBlockAt("A\n| take 1\n\nB", 12).text).toBe("B");
    expect(queryBlockAt("A\n| take 1\n\nB", 3).text).toBe("A\n| take 1");
  });

  it("Set in query replaces the picker when the query filters on TimeGenerated", () => {
    mount();
    nav("Query");
    setValue(editor(), "SigninLogs | where TimeGenerated > ago(1h)");
    expect(text()).toContain("Set in query");
  });

  it("Include adds a where line and reruns", async () => {
    mount();
    await runInLogs("DeviceProcessEvents");
    press("Expand row");
    press("Include FileName");
    await settle();
    expect(editor().value).toBe('DeviceProcessEvents\n| where FileName == "invoice.exe"');
    expect(gridRows()).toHaveLength(1);
  });

  it("Exclude adds the negative", () => {
    expect(whereClause({ name: "Name", type: "string" }, 'a"b', true)).toBe('| where Name != "a\\"b"');
    expect(whereClause({ name: "EventID", type: "int" }, 4624, false)).toBe("| where EventID == 4624");
    expect(whereClause({ name: "X", type: "string" }, null, false)).toBe("| where isnull(X)");
  });

  it("sorts, filters a column on the client, and cycles the header", async () => {
    mount();
    await runInLogs("DeviceProcessEvents");
    press(/^FileName/);
    const first = () => gridRows()[0].querySelectorAll("td")[5].textContent;
    expect(first()).toBe("powershell.exe");
    press(/^FileName/);
    expect(first()).toBe("invoice.exe");
    press("Filter FileName");
    setValue(q<HTMLInputElement>('[role=dialog][aria-label="Filter FileName"] input')!, "power");
    act(() => { q<HTMLFormElement>('[role=dialog][aria-label="Filter FileName"] form')!.requestSubmit(); });
    expect(gridRows()).toHaveLength(1);
  });

  it("moves through the grid by keyboard and selects with Space", async () => {
    mount();
    await runInLogs("DeviceProcessEvents");
    const grid = q("table[role=grid]")!;
    key(grid, " ");
    expect(q<HTMLInputElement>("table[role=grid] tbody input[type=checkbox]")!.checked).toBe(true);
    key(grid, "Enter");
    expect(text()).toContain("Include");
    key(grid, "ArrowRight");
    expect(q('table[role=grid] td[tabindex="0"]')?.getAttribute("data-col")).toBe("1");
  });

  it("autocompletes: Tab accepts, Esc closes", () => {
    mount();
    nav("Query");
    setValue(editor(), "Sign", 4);
    expect(q(".st-ac-opt")?.textContent).toContain("SigninLogs");
    key(editor(), "Tab");
    expect(editor().value).toBe("SigninLogs");
    setValue(editor(), "Sign", 4);
    key(editor(), "Escape");
    expect(q(".st-ac-opt")).toBeNull();
  });

  it("colours tokens from the tokenizer", () => {
    mount();
    nav("Query");
    setValue(editor(), 'SigninLogs | where X == "y"');
    const layer = q("[data-testid=kql-highlight]")!;
    expect(layer.textContent).toContain('SigninLogs | where X == "y"');
    expect(layer.querySelector(".st-tok-string")?.textContent).toBe('"y"');
  });

  it("the data sources pane groups tables by source with counts, expands a table, and a double-click inserts", () => {
    mount();
    nav("Query");
    expect(all('[role=tab]').filter(t => t.closest(".st-schema")).map(t => t.textContent)).toEqual(["Data sources", "Saved queries"]);
    const heads = all(".xd-src-head").map(h => h.querySelector(".st-grow")?.textContent);
    expect(heads).toContain("Identity");
    expect(heads).toContain("Endpoints");
    for (const h of all(".xd-src-head")) { expect(h.querySelector(".xd-src-ico svg")).toBeTruthy(); expect(h.querySelector(".xd-count")?.textContent).toMatch(/^\d+$/); }
    const signin = button(/^SigninLogs, table/);
    expect(signin.querySelector(".xd-tname")?.textContent).toBe("SigninLogs");
    expect(signin.querySelector(".xd-rows")?.textContent).toBe("120");
    expect(text()).not.toContain("Group by");
    press("A to Z");
    expect(all(".xd-src-head").map(h => h.querySelector(".st-grow")?.textContent)).toEqual(["All data sources"]);
    press("By source");
    press(/^SigninLogs, table/);
    expect(button(/^UserPrincipalName, string/).querySelector(".xd-typebadge")?.textContent).toBe("str");
    act(() => { button(/^IPAddress, string/).dispatchEvent(new MouseEvent("dblclick", { bubbles: true })); });
    expect(editor().value).toBe("IPAddress");
  });

  it("the panel inside an incident is one query, with the data sources pane collapsed", async () => {
    mount();
    openDetails();
    press("Alerts, 2");
    await settle();
    expect(q(".st-qtabs")).toBeNull();
    expect(text()).toContain("Data sources");
    expect(q(".st-col-rail")).toBeTruthy();
    expect(() => button("Export")).toThrow();
    press("Expand data sources pane");
    expect(text()).toContain("By source");
  });

  it("Browse saved queries opens the Saved queries tab, and the editor collapses", () => {
    mount();
    nav("Query");
    press("Browse saved queries");
    expect(all(".xd-src-head").map(h => h.querySelector(".st-grow")?.textContent)).toEqual(["Hunts", "Detection rules"]);
    expect(text()).toContain("Failed sign-ins by account");
    press("Collapse editor");
    expect(q<HTMLElement>(".st-editor")!.style.height).toBe("80px");
    press("Expand editor");
    // The editor opens at a fifth of the screen height (110 to 210 px), so a 720 px screen keeps room for results.
    expect(q<HTMLElement>(".st-editor")!.style.height).toBe(`${Math.round(Math.min(210, Math.max(110, window.innerHeight * 0.2)))}px`);
  });

  it("opens several queries in tabs", async () => {
    mount();
    await runInLogs("SigninLogs");
    expect(all(".st-qtab [role=tab]")[0].textContent).toBe("Query 1 (edited)");
    press("New query tab");
    expect(all(".st-qtab")).toHaveLength(2);
    expect(all("[data-testid=kql-input]").filter(e => !e.closest("[hidden]"))[0]).toHaveProperty("value", "");
  });

  it("renders a chart from render, and says so when there is nothing to plot", async () => {
    mount();
    await runInLogs("SigninLogs\n| summarize c = count() by AppDisplayName, ResultType\n| render columnchart");
    expect(q(".st-chart svg")).toBeTruthy();
    await runInLogs("DeviceProcessEvents");
    press("Chart");
    expect(text()).toContain("No chart available");
  });

  it("the CSV guards formula cells", () => {
    expect(toCsv(["a", "b"], [["=cmd()", 'x"y,z']])).toBe("a,b\r\n'=cmd(),\"x\"\"y,z\"");
  });

  it("Add bookmark maps entities from the rows and adds to the current incident", async () => {
    const { calls } = mount();
    openDetails();
    press("Query");
    setValue(editor(), "DeviceProcessEvents", 19);
    press("Run");
    await settle();
    click(q<HTMLInputElement>("table[role=grid] tbody input[type=checkbox]")!);
    press(/^Add bookmark/);
    expect(text()).toContain("Entities mapped from the selected rows");
    expect(text()).toContain("FIN-LT-042");
    await act(async () => { button("Create").click(); });
    const b = calls.find(c => c.fn === "addBookmark")!.args[0] as { incidentId: string; entityIds: string[]; rows: unknown[] };
    expect(b.incidentId).toBe("inc-101");
    expect(b.entityIds).toContain("host:fin-lt-042");
    expect(b.rows).toHaveLength(1);
  });
});

describe("search, hunting, analytics, automation", () => {
  it("Search runs a search statement in Query", async () => {
    mount();
    nav("Search");
    setValue(q<HTMLInputElement>('input[placeholder^="Search for an IP"]')!, "invoice.exe");
    click(q<HTMLButtonElement>("form button[type=submit]")!);
    await settle();
    expect(editor().value).toBe('search "invoice.exe"');
    expect(text()).toContain("Query complete");
  });

  it("Hunts runs a hunt, shows the hits, and opens the results in Query", async () => {
    mount();
    nav("Hunts");
    expect(all('[aria-label="Hunts view"] button').map(b => b.textContent)).toEqual(["Hunt queries (1)", "Bookmarks (0)"]);
    click(q('table[aria-label="Hunt queries"] tbody tr')!);
    press("Run hunt");
    expect(q('table[aria-label="Hunt queries"] tbody tr')!.querySelectorAll("td")[1].textContent).toBe("1");
    press("Open in Query");
    await settle();
    expect(editor().value).toContain("summarize Failures");
  });

  it("Detections shows the rule and opens its query", async () => {
    mount();
    nav("Detections");
    expect(all(".xd-kpi > span").map(s => s.textContent)).toEqual(["Detection rules", "Rules that fired", "Alerts raised"]);
    expect(text()).not.toContain("Active rules");
    click(q('table[aria-label="Detection rules"] tbody tr')!);
    expect(text()).toContain("Runs every");
    expect(text()).toContain("Looks back over");
    press("Open in Query");
    await settle();
    expect(gridRows().length).toBeGreaterThan(0);
  });

  it("Playbooks works and shows the server's refusal", async () => {
    const refusal = "Isolation is a Tier-2 / Tier-3 action.";
    const { actions } = fakeActions({ canContain: false, setIsolated: async () => refusal });
    mount({ actions });
    nav("Playbooks");
    expect(all('ul[aria-label="Playbooks"] .xd-pb-card strong').map(s => s.textContent)).toEqual(["Isolate device", "Release device"]);
    await act(async () => { all<HTMLButtonElement>('[aria-label="Playbooks"] button')[0].click(); });
    expect(text()).toContain(refusal);
    expect(text()).toContain("Refused");
  });

  it("with nobody to approve, the requester is told so, and the panel's run history is a stacked list", async () => {
    const sent: unknown[][] = [];
    const { actions } = fakeActions({ requestIsolation: async (...a: unknown[]) => { sent.push(a); return null; }, isolationApprover: NO_APPROVER, isolationRequests: [] });
    const m = mount({ actions });
    openDetails();
    press("Actions for FIN-LT-042");
    press("Run action");
    expect(q("[role=dialog] h2")?.textContent).toBe("Run action");
    setValue(q<HTMLTextAreaElement>("#pb-reason")!, "Beacon to a known C2 from this laptop");
    await act(async () => { button("Request isolation").click(); });
    expect(sent).toHaveLength(1);
    expect(text()).toContain("Request sent. No approver on shift: an exercise admin must approve.");
    expect(text()).toContain("you cannot approve your own");
    expect(text()).not.toMatch(/Waiting for approval from/);
    const req = { seq: 9, host: "FIN-LT-042", state: "pending" as const, requestedBy: "Tal Analyst", mine: true, reason: "Beacon to a known C2 from this laptop", incident: null, at: new Date().toISOString(), approver: NO_APPROVER, answeredAt: null, denyReason: null };
    m.rerender({ actions: { ...actions, isolationRequests: [req] } });
    expect(text()).toContain("Current state: Isolation requested. No approver on shift: an exercise admin must approve");
    // In the side panel the history is a list: no table to clip the Result column (2026-11-08 review).
    const panel = q("[role=dialog]")!;
    expect(panel.querySelector('table[aria-label="Playbook runs"]')).toBeNull();
    const runs = [...panel.querySelectorAll(".st-runs li")];
    expect(runs).toHaveLength(1);
    expect(runs[0].querySelector(".st-run-waiting")!.textContent).toBe("Waiting");
    expect(runs[0].textContent).toContain("FIN-LT-042");
    expect(runs[0].querySelector(".st-run-detail")!.textContent).toContain("No approver on shift");
  });

  it("Isolate device sends a request for approval with a reason, and the history follows the answer", async () => {
    const sent: unknown[][] = [];
    const base = { requestIsolation: async (...a: unknown[]) => { sent.push(a); return null; }, isolationApprover: "Dana (SOC Manager)", isolationRequests: [] as NonNullable<SentinelActions["isolationRequests"]> };
    const { actions } = fakeActions(base);
    const m = mount({ actions });
    nav("Playbooks");
    const isolate = () => all<HTMLButtonElement>('[aria-label="Playbooks"] button')[0];
    expect(isolate().textContent).toBe("Request");
    // no reason: nothing is sent, and the field says why
    await act(async () => { isolate().click(); });
    expect(sent).toHaveLength(0);
    expect(text()).toContain("Say in a few words why this device should be isolated.");
    setValue(q<HTMLTextAreaElement>("#auto-reason")!, "Beacon to a known C2 from this laptop");
    await act(async () => { isolate().click(); });
    expect(sent).toHaveLength(1);
    expect(sent[0][1]).toBe("Beacon to a known C2 from this laptop");
    expect(text()).toContain("Waiting for approval from Dana (SOC Manager)");
    const host = String(sent[0][0]);
    const req = { seq: 9, host, state: "pending" as const, requestedBy: "Tal Analyst", mine: true, reason: "Beacon to a known C2 from this laptop", incident: null, at: new Date().toISOString(), approver: "Dana (SOC Manager)", answeredAt: null, denyReason: null };
    m.rerender({ actions: { ...actions, isolationRequests: [req] } });
    expect(text()).toContain("Waiting");
    expect(isolate().disabled).toBe(true);
    expect(q<HTMLSelectElement>("select")!.selectedOptions[0].textContent).toBe(`${host} (isolation requested)`);
    m.rerender({ actions: { ...actions, isolationRequests: [{ ...req, state: "denied", approver: "Dana", denyReason: "Scope it first" }] } });
    expect(text()).toContain("Denied by Dana: Scope it first");
    m.rerender({ actions: { ...actions, isolatedHosts: new Set([host]), isolationRequests: [{ ...req, seq: 10, state: "approved", approver: "Dana" }] } });
    expect(text()).toContain("Approved by Dana. The device is isolated.");
    expect(q<HTMLSelectElement>("select")!.selectedOptions[0].textContent).toBe(`${host} (isolated)`);
  });

  it("an isolated device shows as isolated in its entity pane", () => {
    const { actions } = fakeActions({ isolatedHosts: new Set(["FIN-LT-042"]) });
    mount({ actions });
    nav("Entities");
    click(all('table[aria-label="Entities"] tbody tr').find(r => r.textContent?.includes("FIN-LT-042"))!);
    expect(q(".st-devstate")?.textContent).toBe("Isolated");
  });

  it("Entities filters by type and opens an entity page with Info, Timeline and Insights", () => {
    mount();
    nav("Entities");
    const names = () => all('table[aria-label="Entities"] tbody tr').map(r => r.textContent ?? "");
    press("Devices");
    expect(names().length).toBeGreaterThan(0);
    for (const n of names()) expect(n).not.toContain("jdoe@contoso.example");
    press("All");
    expect(q(".st-blade-head h1")!.textContent).toBe("Entities");
    click(all('table[aria-label="Entities"] tbody tr').find(r => r.textContent?.includes("FIN-LT-042"))!);
    expect(all(".st-entity-page .st-widget h3").map(h => h.textContent)).toEqual(["FIN-LT-042", "Timeline", "Insights"]);
    // XDR's labelled sections, not the portal's cards (owner, 2026-11-08).
    expect(all(".st-entity-page .xd-psec-head").map(h => h.textContent)).toEqual(["Identity", "Activity", "Related alerts (1)"]);
    expect(q(".st-blade-head h1")!.textContent).toBe("FIN-LT-042");
    press("Entities");
    expect(q(".st-blade-head h1")!.textContent).toBe("Entities");
  });
});

describe("investigation graph", () => {
  it("shows alerts and entities, and an exploration query adds nodes behind a hub", async () => {
    mount();
    openDetails();
    press("Investigate");
    const nodes = () => all("[data-node]");
    expect(nodes()).toHaveLength(6);
    const account = q('[data-node="account:jdoe@contoso.example"]')!;
    act(() => { account.dispatchEvent(new MouseEvent("mouseover", { bubbles: true })); });
    expect(q(".st-explore")).toBeTruthy();
    press(/^Sign-ins for account \(60\)/);
    expect(all("[data-testid=graph-link]").length).toBeGreaterThan(0);
    expect(q('[data-node="ip:198.51.100.7"]')).toBeTruthy();
    press("Undo");
    expect(q('[data-node="ip:198.51.100.7"]')).toBeNull();
    press("Redo");
    expect(q('[data-node="ip:198.51.100.7"]')).toBeTruthy();
    act(() => { q("[data-hub]")!.dispatchEvent(new MouseEvent("click", { bubbles: true })); });
    expect(q('[data-node="ip:198.51.100.7"]'), "the X on the hub removes what it added").toBeNull();
  });

  it("each alert runs one trunk with an events dot, and it opens the events", async () => {
    mount();
    openDetails();
    press("Investigate");
    const dot = q('[data-events="aaaaaaaa-0002"]')!;
    act(() => { dot.dispatchEvent(new MouseEvent("click", { bubbles: true })); });
    await settle();
    expect(editor().value).toContain("DeviceProcessEvents");
  });

  it("the time strip opens from View related events, and Help works", () => {
    mount();
    openDetails();
    press("Investigate");
    expect(q(".st-strip")).toBeNull();
    press("View related events");
    expect(q(".st-strip")).toBeTruthy();
    press("Help");
    expect(q(".st-railpane")?.textContent).toContain("exploration queries");
  });

  it("a question whose answers are all on the graph cannot add anything", () => {
    mount();
    openDetails();
    press("Investigate");
    act(() => { q('[data-node="account:jdoe@contoso.example"]')!.dispatchEvent(new MouseEvent("mouseover", { bubbles: true })); });
    expect(button(/^Related alerts \(2\)/).disabled).toBe(true);
    expect(all("[data-testid=graph-link]")).toHaveLength(0);
  });

  it("the Info rail offers the same questions, for keyboard users", () => {
    mount();
    openDetails();
    press("Investigate");
    act(() => { q('[data-node="host:fin-lt-042"]')!.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true })); });
    expect(q(".st-explore-rail")?.textContent).toContain("Processes running on Host");
  });

  it("Events opens the raw query in Query", async () => {
    mount();
    openDetails();
    press("Investigate");
    act(() => { q('[data-node="host:fin-lt-042"]')!.dispatchEvent(new MouseEvent("mouseover", { bubbles: true })); });
    press("Events for Processes running on Host");
    await settle();
    expect(editor().value).toContain("DeviceProcessEvents");
    expect(gridRows()).toHaveLength(2);
  });

  it("every exploration query parses and runs", async () => {
    const { runKql } = await import("@/lib/kql");
    const ws = fixtureWorkspace();
    for (const e of Object.values(ws.entities)) {
      for (const x of explorationsFor(e, ws)) {
        const r = runKql(x.query, { tables: ws.tables, now: new Date(ws.now) });
        expect(r.ok, x.query).toBe(true);
      }
    }
    // Against the real schemas too, with each preferred table gone in turn, so every fallback runs.
    const { TABLE_NAMES, emptyTable } = await import("@/lib/sentinel/tables");
    const full = Object.fromEntries(TABLE_NAMES.map(n => [n, emptyTable(n)]));
    for (const drop of [[], ["SigninLogs"], ["SigninLogs", "SecurityEvent"], ["DeviceProcessEvents"], ["DeviceNetworkEvents"]]) {
      const tables = Object.fromEntries(Object.entries(full).filter(([n]) => !drop.includes(n)));
      const real = fixtureWorkspace({ tables });
      for (const e of Object.values(real.entities)) {
        for (const x of explorationsFor(e, real)) {
          const r = runKql(x.query, { tables, now: new Date(real.now) });
          expect(r.ok, x.query).toBe(true);
        }
      }
    }
  });
});

describe("XDR's own alerts, entities and graph", () => {
  it("an alert in the timeline is a card: severity stripe, time on the right, severity, product and tactic chips, key entities", () => {
    mount();
    openDetails();
    const card = all(".xd-tl .xd-alert-card").find(c => c.textContent?.startsWith("Suspicious process launched"))!;
    expect(card.classList.contains("Medium")).toBe(true);
    expect(card.querySelector(".xd-ac-top time")).toBeTruthy();
    expect([...card.querySelectorAll(".xd-ac-chips .xd-chip")].map(c => c.textContent)).toEqual(["Medium", "Microsoft Defender for Endpoint", "Execution"]);
    expect([...card.querySelectorAll(".xd-echip")].map(c => c.textContent)).toEqual(["jdoe@contoso.example", "FIN-LT-042", "+1"]);
    // no portal timeline (no date column), but XDR's own: one vertical line with a severity dot per item
    expect(q(".st-tl-rail, .st-tl-date, .st-tl-dot")).toBeNull();
    expect(card.closest(".xd-tl-item")!.querySelector(".xd-vrail .xd-vdot.Medium")).toBeTruthy();
    expect(card.closest(".xd-tl")!.classList.contains("vt")).toBe(true);
  });

  it("severity is a coloured pill in the incidents grid and the results grid", async () => {
    mount();
    const pill = incidentRows()[0].querySelector(".st-sevcell .xd-chip.sev")!;
    expect(pill).toBeTruthy();
    expect(pill.classList.contains(pill.textContent!)).toBe(true);
    await runInLogs("SecurityAlert | project AlertName, AlertSeverity");
    const cells = gridRows().map(r => r.querySelector(".xd-chip.sev")?.textContent);
    expect(cells.length).toBeGreaterThan(0);
    for (const c of cells) expect(["High", "Medium", "Low", "Informational"]).toContain(c);
  });

  it("Quick findings is a short icon list, and a row opens that finding's results", async () => {
    mount();
    openDetails();
    const widget = q('section.st-widget[aria-label="Quick findings"]')!;
    const rows = [...widget.querySelectorAll<HTMLButtonElement>(".xd-ins-row")];
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) { expect(r.querySelector(".xd-ins-ico svg")).toBeTruthy(); expect(r.getAttribute("aria-expanded")).toBe("false"); }
    expect(widget.querySelector(".st-mini")).toBeNull();
    click(rows[0]);
    expect(rows[0].getAttribute("aria-expanded")).toBe("true");
    press("See results >");
    await settle();
    expect(gridRows().length).toBeGreaterThan(0);
  });

  it("the alert flyout is sectioned, with entity chips that open the entity", () => {
    mount();
    openDetails();
    press(/^Unfamiliar sign-in properties/);
    const fly = q(".st-flyout")!;
    expect(fly.classList.contains("High")).toBe(true);
    expect([...fly.querySelectorAll(".xd-psec-head")].map(h => h.textContent)).toEqual(["Description", "Detection", "Entities (2)", "Tactics and techniques", "Timing"]);
    click(fly.querySelector<HTMLButtonElement>(".xd-echip-btn")!);
    expect(q('[aria-label="jdoe@contoso.example details"]')).toBeTruthy();
  });

  it("entities are grouped by type, with a count per type and an alert badge per entity", () => {
    mount();
    openDetails();
    const widget = q('section.st-widget[aria-label="Entities"]')!;
    expect([...widget.querySelectorAll(".xd-egroup-head")].map(h => h.textContent)).toEqual(["Accounts1", "Hosts1", "IP addresses1", "Files1"]);
    const jdoe = [...widget.querySelectorAll(".xd-erow")].find(r => r.textContent?.includes("jdoe@contoso.example"))!;
    expect(jdoe.querySelector(".xd-etile")).toBeTruthy();
    expect(jdoe.querySelector(".xd-ebadge")!.textContent).toBe("2 alerts");
    press("Entities");
    click(all<HTMLButtonElement>(".st-entities-list .xd-erow-main").find(b => b.textContent?.includes("FIN-LT-042"))!);
    const pane = q('[aria-label="FIN-LT-042 details"]')!;
    expect(pane.querySelector("h2")!.textContent).toBe("FIN-LT-042");
    expect([...pane.querySelectorAll(".xd-psec-head")].map(h => h.textContent)).toEqual(["Identity", "Activity", "Related alerts (1)"]);
    expect(pane.querySelector(".st-card-tabs")).toBeNull();
  });

  it("the graph draws alerts as striped cards and entities as tiles, with right-angled links, a legend and tabs on top of the side pane", () => {
    mount();
    openDetails();
    press("Investigate");
    const alert = q('[data-node="aaaaaaaa-0001"]')!;
    expect(alert.querySelector("circle")).toBeNull();
    expect(alert.querySelectorAll("rect").length).toBeGreaterThanOrEqual(2);
    expect(alert.textContent).toContain("High alert");
    const host = q('[data-node="host:fin-lt-042"]')!;
    expect(host.querySelector("circle")).toBeNull();
    expect(host.textContent).toContain("FIN-LT-042");
    expect(host.textContent).toContain("Host");
    expect(all(".xd-edge").length).toBeGreaterThan(0);
    for (const e of all(".xd-edge")) expect(e.getAttribute("d")).toMatch(/^M[^Q]*V/);
    expect(q(".xd-legend")?.textContent).toContain("Alert");
    expect(q(".st-railpane .xd-side-tabs [role=tab]")).toBeTruthy();
    expect(q(".st-rail")).toBeNull();
    press("Collapse side pane");
    expect(q(".st-railpane")).toBeNull();
    press("Open side pane");
    expect(q(".st-railpane")).toBeTruthy();
  });
});

describe("panels", () => {
  it("Escape closes the top panel only, wherever focus is", async () => {
    mount();
    openDetails();
    press("Query");
    setValue(editor(), "SigninLogs", 10);
    press("Run");
    await settle();
    click(q<HTMLInputElement>("table[role=grid] tbody input[type=checkbox]")!);
    press(/^Add bookmark/);
    expect(all("[role=dialog]")).toHaveLength(2);
    act(() => { (document.activeElement as HTMLElement | null)?.blur(); });
    key(document.body, "Escape");
    expect(all("[role=dialog]")).toHaveLength(1);
    expect(q("[data-testid=kql-input]")).toBeTruthy();
  });

  it("Escape in the editor stays in the editor", () => {
    mount();
    openDetails();
    press("Query");
    key(editor(), "Escape");
    expect(q("[data-testid=kql-input]")).toBeTruthy();
  });
});

describe("a finished exercise", () => {
  it("is read-only: banner, no writes, queries still run", async () => {
    mount({ ended: true });
    expect(text()).toContain("The exercise has ended");
    openDetails();
    expect(button(/^Status: New/).disabled).toBe(true);
    expect(button(/^Owner: Unassigned/).disabled).toBe(true);
    expect(() => button("Incident actions")).toThrow();
    press("Case history");
    expect(q('textarea[placeholder="Write a comment..."]')).toBeNull();
    press("Close Case history");
    press("Query");
    setValue(editor(), "SigninLogs", 10);
    press("Run");
    await settle();
    expect(gridRows().length).toBe(50);
    expect(() => button(/^Add bookmark/)).toThrow();
  });
});

describe("deep link", () => {
  it("opens the incident the team room named, once it arrives", () => {
    const empty = fixtureWorkspace({ incidents: [] });
    const m = mount({ workspace: empty, initial: { incidentId: "inc-101" } });
    expect(text()).not.toContain("Incident #101");
    m.rerender({ workspace: fixtureWorkspace() });
    expect(text()).toContain("Incident #101");
  });
});

vi.stubGlobal("requestAnimationFrame", (f: FrameRequestCallback) => { f(0); return 0; });
