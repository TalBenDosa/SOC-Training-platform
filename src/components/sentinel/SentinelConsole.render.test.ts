// The console end to end on a tiny workspace: the screens an analyst walks through, against the real
// KQL engine and a fake SentinelActions. What a person would see and press, not component internals.
import { describe, it, expect, afterEach, vi } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { SentinelConsole, type SentinelConsoleProps } from "./SentinelConsole";
import { fakeActions, fixtureState, fixtureWorkspace, INCIDENTS } from "./fixture";
import { CLASSIFICATIONS, explorationsFor, queryBlockAt, toCsv, whereClause } from "./helpers";
import type { IncidentState, SentinelIncident } from "@/lib/sentinel/types";

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

const nav = (name: string) => click(all<HTMLButtonElement>(".st-nav-item").find(b => b.textContent === name)!);
const editor = () => q<HTMLTextAreaElement>("[data-testid=kql-input]")!;
async function runInLogs(query: string) {
  nav("Logs");
  setValue(editor(), query, query.length);
  press("Run");
  await settle();
}
const gridRows = () => all("table[role=grid] tbody tr[data-row]");
const incidentRows = () => all('table[aria-label="Incidents"] tbody tr');

describe("shell", () => {
  it("has the requested menu and nothing else", () => {
    mount();
    expect(all(".st-nav-item").map(b => b.textContent)).toEqual(["Overview", "Logs", "Search", "Incidents", "Hunting", "Entity behavior", "Threat intelligence", "Analytics", "Automation"]);
    expect(all(".st-nav-group").map(b => b.textContent)).toEqual(["General", "Threat management", "Configuration"]);
    expect(text()).toContain("contoso-sentinel-prod");
    expect(q<HTMLAnchorElement>(".st-topbar a")!.textContent).toBe("Back to team room");
  });

  it("every screen renders, every control has a name, no em dash in the text", async () => {
    mount();
    for (const s of ["Overview", "Logs", "Search", "Incidents", "Hunting", "Entity behavior", "Threat intelligence", "Analytics", "Automation"]) {
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
    expect(kpi[0]).toBe("1Open incidents");
    expect(kpi[1]).toBe("1New incidents");
    expect(kpi[2]).toBe("0Active incidents");
  });

  it("sorts by a column and filters by the search box", () => {
    mount();
    const numbers = () => incidentRows().map(r => r.querySelectorAll("td")[1].textContent);
    expect(numbers()).toEqual(["102", "101"]);
    press(/^Incident number/);
    press(/^Incident number/);
    expect(numbers()).toEqual(["101", "102"]);
    setValue(q<HTMLInputElement>('input[placeholder^="Search by ID"]')!, "service");
    expect(numbers()).toEqual(["102"]);
  });

  it("opens the preview, and changing the owner there writes through the actions", () => {
    const { calls } = mount();
    click(incidentRows().find(r => r.textContent?.includes("Initial access"))!);
    expect(text()).toContain("View full details");
    press(/^Owner: Unassigned/);
    press("Dana Lead");
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
    expect(text()).toContain("Incident ID 103");
    expect(q(".st-toast")).toBeNull();
    press("Close incident");
    expect(q(".st-new-mark")).toBeNull();
  });
});

function openDetails(name = "Initial access") {
  click(incidentRows().find(r => r.textContent?.includes(name))!);
  press("View full details");
}

describe("incident details", () => {
  it("moves focus into the blade, and back to what opened it", async () => {
    mount();
    click(incidentRows().find(r => r.textContent?.includes("Initial access"))!);
    const opener = button("View full details");
    opener.focus();
    act(() => { opener.click(); });
    expect(document.activeElement?.className).toBe("st-inc");
    press("Close incident");
    await settle();
    expect(document.activeElement?.textContent).toBe("View full details");
  });

  it("lays out the left panel, toolbar and four widgets", () => {
    mount();
    openDetails();
    expect(text()).toContain("Incident ID 101");
    for (const label of ["Refresh", "Logs", "Tasks", "Activity log", "Investigate", "Incident actions", "Overview", "Entities"]) expect(button(label)).toBeTruthy();
    for (const label of ["Workspace name", "Description", "Alert product names", "Evidence", "Last update time", "Creation time", "Tactics and techniques"]) expect(text()).toContain(label);
    expect(all(".st-widget h3").map(h => h.textContent)).toEqual(["Incident timeline", "Entities", "Top insights", "Similar incidents "]);
  });

  it("Evidence opens the Logs panel on its query, already run, and Done closes it", async () => {
    const { calls } = mount();
    openDetails();
    press("Alerts, 2");
    await settle();
    expect(q('[role=dialog][aria-labelledby]')?.textContent).toContain("Logs");
    expect(editor().value).toContain("SystemAlertId in");
    expect(text()).toContain("Completed. Showing results from the last 24 hours.");
    expect(gridRows()).toHaveLength(2);
    expect(calls.find(c => c.fn === "queryRan")).toBeTruthy();
    press("Done");
    expect(q("[data-testid=kql-input]")).toBeNull();
  });

  it("a timeline item shows the alert details, and the System alert ID goes to Logs", async () => {
    mount();
    openDetails();
    press(/^Suspicious process launched/);
    expect(text()).toContain("System alert ID");
    press("aaaaaaaa-0002");
    await settle();
    expect(editor().value).toContain("DeviceProcessEvents");
    expect(gridRows()).toHaveLength(2);
  });

  it("closing needs a classification from the five real values, and reopen works", () => {
    const { calls, rerender, base } = mount();
    openDetails();
    press(/^Status: New/);
    press("Closed");
    const dialog = q('[role=dialog][aria-label="Close incident"]')!;
    const select = dialog.querySelector("select") as HTMLSelectElement;
    expect([...select.options].map(o => o.value).filter(Boolean)).toEqual(CLASSIFICATIONS);
    expect(button("Apply").disabled).toBe(true);
    setValue(select, CLASSIFICATIONS[1]);
    setValue(dialog.querySelector("textarea") as HTMLTextAreaElement, "Admin was patching");
    press("Apply");
    expect(calls.find(c => c.fn === "updateIncident")?.args).toEqual(["inc-101", { status: "Closed", classification: CLASSIFICATIONS[1], closingComment: "Admin was patching" }]);

    const states = new Map(base.states);
    states.set("inc-101", fixtureState({ status: "Closed", classification: CLASSIFICATIONS[1] }));
    rerender({ states });
    press(/^Status: Closed/);
    press("Active");
    expect(calls.filter(c => c.fn === "updateIncident").at(-1)?.args).toEqual(["inc-101", { status: "Active" }]);
  });

  it("Tasks and Activity log are live, and a comment goes through the actions", async () => {
    const { calls, rerender, base } = mount();
    openDetails();
    press("Activity log");
    const box = q<HTMLTextAreaElement>('textarea[placeholder="Write a comment..."]')!;
    setValue(box, "Checked the sign-in");
    await act(async () => { button("Comment").click(); });
    expect(calls.find(c => c.fn === "addComment")?.args).toEqual(["inc-101", "Checked the sign-in"]);
    const states = new Map(base.states);
    states.set("inc-101", fixtureState({ comments: [{ id: "c1", author: "Dana Lead", text: "Seen, thanks", at: "2026-01-01T09:00:00.000Z" }] }));
    rerender({ states });
    expect(text()).toContain("Seen, thanks");
    press("Close Incident activity log");

    press("Tasks");
    click(q<HTMLInputElement>('[role=dialog] input[type=checkbox]')!);
    expect(calls.find(c => c.fn === "setTask")?.args).toEqual(["inc-101", "Review the alerts", true]);
  });

  it("entity menu offers only what the product allows for the kind", () => {
    mount();
    openDetails();
    press("Actions for FIN-LT-042");
    expect(all("[role=menuitem]").map(i => i.textContent)).toEqual(["Run playbook"]);
    key(q("[role=menu]")!, "Escape");
    press("Actions for 203.0.113.50");
    expect(all("[role=menuitem]").map(i => i.textContent)).toEqual(["Add to TI"]);
    key(q("[role=menu]")!, "Escape");
    expect(el!.querySelector('[aria-label="Actions for jdoe@contoso.example"]')).toBeNull();
  });

  it("Add to TI lands on the Threat intelligence screen", async () => {
    const { calls, rerender, base } = mount();
    openDetails();
    press("Actions for 203.0.113.50");
    await act(async () => { button("Add to TI").click(); });
    const comment = calls.find(c => c.fn === "addComment")!.args as [string, string];
    const states = new Map(base.states);
    states.set("inc-101", fixtureState({ comments: [{ id: "c1", author: "Tal Analyst", text: comment[1], at: "2026-01-01T09:00:00.000Z" }] }));
    rerender({ states });
    press("Close incident");
    nav("Threat intelligence");
    const row = q('table[aria-label="Threat indicators"] tbody tr')!;
    expect(row.textContent).toContain("203.0.113.50");
    expect(row.textContent).toContain("Tal Analyst");
  });
});

describe("logs", () => {
  it("runs on Shift+Enter and reports status, row count and UTC", async () => {
    mount();
    nav("Logs");
    setValue(editor(), "SigninLogs", 10);
    key(editor(), "Enter", { shiftKey: true });
    await settle();
    expect(text()).toContain("Completed. Showing results from the last 24 hours.");
    expect(text()).toContain("120 records");
    expect(text()).toContain("Display time (UTC+00:00)");
    expect(text()).toContain("TimeGenerated [UTC]");
  });

  it("pages at 50 and moves between pages", async () => {
    mount();
    await runInLogs("SigninLogs");
    expect(gridRows()).toHaveLength(50);
    expect(text()).toContain("1 - 50 of 120");
    press("Next page");
    expect(text()).toContain("51 - 100 of 120");
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
    nav("Logs");
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
    nav("Logs");
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
    nav("Logs");
    setValue(editor(), 'SigninLogs | where X == "y"');
    const layer = q("[data-testid=kql-highlight]")!;
    expect(layer.textContent).toContain('SigninLogs | where X == "y"');
    expect(layer.querySelector(".st-tok-string")?.textContent).toBe('"y"');
  });

  it("the schema pane expands a table, and a double-click inserts", () => {
    mount();
    nav("Logs");
    press(/^SigninLogs, table/);
    expect(text()).toContain("UserPrincipalName (string)");
    act(() => { button(/^IPAddress, string/).dispatchEvent(new MouseEvent("dblclick", { bubbles: true })); });
    expect(editor().value).toBe("IPAddress");
  });

  it("opens several queries in tabs", async () => {
    mount();
    await runInLogs("SigninLogs");
    press("New Query");
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
    press("Logs");
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
  it("Search runs a search statement in Logs", async () => {
    mount();
    nav("Search");
    setValue(q<HTMLInputElement>('input[placeholder^="Search for an IP"]')!, "invoice.exe");
    click(q<HTMLButtonElement>("form button[type=submit]")!);
    await settle();
    expect(editor().value).toBe('search "invoice.exe"');
    expect(text()).toContain("Completed.");
  });

  it("Hunting runs a query, shows the count, and views results in Logs", async () => {
    mount();
    nav("Hunting");
    click(q('table[aria-label="Hunting queries"] tbody tr')!);
    press("Run query");
    expect(q('table[aria-label="Hunting queries"] tbody tr')!.querySelectorAll("td")[1].textContent).toBe("1");
    press("View results");
    await settle();
    expect(editor().value).toContain("summarize Failures");
  });

  it("Analytics shows the rule and opens its query", async () => {
    mount();
    nav("Analytics");
    click(q('table[aria-label="Active rules"] tbody tr')!);
    expect(text()).toContain("Run query every");
    expect(text()).toContain("Lookup data from the last");
    press("Open in Logs");
    await settle();
    expect(gridRows().length).toBeGreaterThan(0);
  });

  it("Automation works and shows the server's refusal", async () => {
    const refusal = "Isolation is a Tier-2 / Tier-3 action.";
    const { actions } = fakeActions({ canContain: false, setIsolated: async () => refusal });
    mount({ actions });
    nav("Automation");
    await act(async () => { all<HTMLButtonElement>('table[aria-label="Playbooks"] button')[0].click(); });
    expect(text()).toContain(refusal);
    expect(text()).toContain("Refused");
  });

  it("Entity behavior opens an entity page with Info, Timeline and Insights", () => {
    mount();
    nav("Entity behavior");
    click(all('table[aria-label="Entities"] tbody tr').find(r => r.textContent?.includes("FIN-LT-042"))!);
    expect(all(".st-entity-page .st-widget h3").map(h => h.textContent)).toEqual(["FIN-LT-042", "Timeline", "Insights"]);
    expect(text()).toContain("Log Activity");
  });
});

describe("investigation graph", () => {
  it("shows alerts and entities, and an exploration query adds nodes with a dotted link", async () => {
    mount();
    openDetails();
    press("Investigate");
    const nodes = () => all("[data-node]");
    expect(nodes()).toHaveLength(6);
    const account = q('[data-node="account:jdoe@contoso.example"]')!;
    act(() => { account.dispatchEvent(new MouseEvent("mouseover", { bubbles: true })); });
    expect(text()).toContain("Exploration queries");
    press(/^Sign-ins for account \(60\)/);
    expect(all("[data-testid=graph-dotted]").length).toBeGreaterThan(0);
    expect(q('[data-node="ip:198.51.100.7"]')).toBeTruthy();
    press("Undo");
    expect(q('[data-node="ip:198.51.100.7"]')).toBeNull();
    press("Redo");
    expect(q('[data-node="ip:198.51.100.7"]')).toBeTruthy();
  });

  it("a question whose answers are all on the graph cannot add anything", () => {
    mount();
    openDetails();
    press("Investigate");
    act(() => { q('[data-node="account:jdoe@contoso.example"]')!.dispatchEvent(new MouseEvent("mouseover", { bubbles: true })); });
    expect(button(/^Related alerts \(2\)/).disabled).toBe(true);
    expect(all("[data-testid=graph-dotted]")).toHaveLength(0);
  });

  it("the Info rail offers the same questions, for keyboard users", () => {
    mount();
    openDetails();
    press("Investigate");
    act(() => { q('[data-node="host:fin-lt-042"]')!.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true })); });
    expect(q(".st-explore-rail")?.textContent).toContain("Processes on host");
  });

  it("Events opens the raw query in Logs", async () => {
    mount();
    openDetails();
    press("Investigate");
    act(() => { q('[data-node="host:fin-lt-042"]')!.dispatchEvent(new MouseEvent("mouseover", { bubbles: true })); });
    press("Events for Processes on host");
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

describe("panels", () => {
  it("Escape closes the top panel only, wherever focus is", async () => {
    mount();
    openDetails();
    press("Logs");
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
    press("Logs");
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
    press("Activity log");
    expect(q('textarea[placeholder="Write a comment..."]')).toBeNull();
    press("Close Incident activity log");
    press("Logs");
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
    expect(text()).not.toContain("Incident ID 101");
    m.rerender({ workspace: fixtureWorkspace() });
    expect(text()).toContain("Incident ID 101");
  });
});

vi.stubGlobal("requestAnimationFrame", (f: FrameRequestCallback) => { f(0); return 0; });
