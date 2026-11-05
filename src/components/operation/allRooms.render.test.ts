// Every room task and every lab must open. A task is only reachable through its Operation
// Mode mechanic, so one crash there blocks the room with no way around it: the Triage Desk
// crashed on opening the decision for every analyst_choice task, because a verdict added to
// the shared list had no style. This walks all of them instead of one sample room.
import { describe, it, expect, vi, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
vi.mock("@/components/rooms/MermaidDiagram", () => ({ MermaidDiagram: () => null }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: () => {}, replace: () => {}, refresh: () => {} }), usePathname: () => "/rooms", useSearchParams: () => new URLSearchParams() }));
import { ROOMS } from "@/data/rooms";
import { sanitizeRoom } from "@/lib/rooms/sanitize";
import { getRoomExperience, mechanicFor } from "@/lib/rooms/experience";
import { ANALYST_VERDICTS } from "@/components/rooms/TaskPlayer";
import { StationTask } from "./OperationView";
import { flattenRaw } from "./shared";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
Element.prototype.scrollIntoView = () => {};
Element.prototype.scrollTo = () => {};
Object.defineProperty(HTMLMediaElement.prototype, "load", { value: () => {}, configurable: true });

const operationRooms = ROOMS
  .map(room => ({ room, safe: sanitizeRoom(room), exp: getRoomExperience(room.id, room.tasks.map(t => t.id)) }))
  .filter(r => r.exp);

describe("every Operation Mode room opens", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); root = null; el?.remove(); el = null; });

  const mount = (roomId: string, task: unknown, labs: unknown) => {
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    const props = { roomId, isCompleted: false, onComplete: () => {}, onMistake: () => {}, onSlow: () => {}, intelTokens: 0, spendToken: () => false };
    act(() => { root!.render(React.createElement(StationTask, { task: task as never, props: props as never, labs: labs as never })); });
  };
  const unmount = () => { act(() => root?.unmount()); root = null; el?.remove(); el = null; };

  it("covers the campaign", () => {
    expect(operationRooms.length).toBeGreaterThanOrEqual(45);
  });

  it("every task and lab renders", () => {
    const failed: string[] = [];
    let n = 0;
    for (const { room, safe, exp } of operationRooms) for (const task of safe.tasks) {
      const labs = exp!.briefings?.[task.id];
      for (const withLabs of labs?.length ? [true, false] : [false]) {
        n++;
        const spy = vi.spyOn(console, "error").mockImplementation(() => {});
        try { mount(room.id, task, withLabs ? labs : undefined); }
        catch (e) { failed.push(`${room.id}/${task.id}${withLabs ? "+labs" : ""}: ${(e as Error).message}`); }
        finally { spy.mockRestore(); try { unmount(); } catch { root = null; el = null; } }
      }
    }
    expect(failed).toEqual([]);
    expect(n).toBeGreaterThan(500);
  }, 280_000);

  it("the Triage Desk opens its decision with every verdict, in every room", () => {
    const failed: string[] = [];
    let desks = 0;
    for (const { room, safe } of operationRooms) for (const task of safe.tasks) {
      if (mechanicFor(task.type) !== "triage_desk") continue;
      desks++;
      const spy = vi.spyOn(console, "error").mockImplementation(() => {});
      try {
        mount(room.id, task, undefined);
        const open = [...el!.querySelectorAll("button")].find(b => /I have read the ticket/.test(b.textContent ?? ""))!;
        act(() => { open.click(); });
        for (const v of ANALYST_VERDICTS) {
          if (![...el!.querySelectorAll("button")].some(b => b.textContent?.startsWith(v.label))) failed.push(`${room.id}/${task.id}: no ${v.key} button`);
        }
      } catch (e) { failed.push(`${room.id}/${task.id}: ${(e as Error).message}`); }
      finally { spy.mockRestore(); try { unmount(); } catch { root = null; el = null; } }
    }
    expect(failed).toEqual([]);
    expect(desks).toBeGreaterThan(0);
  }, 120_000);

  it("a raw field name wraps inside its column, however long", () => {
    for (const { room, safe } of operationRooms) for (const task of safe.tasks) {
      if (mechanicFor(task.type) !== "triage_desk" && mechanicFor(task.type) !== "evidence_board") continue;
      mount(room.id, task, undefined);
      const raw = (task as unknown as { event: { raw: Record<string, unknown> } }).event.raw;
      const names = el!.querySelectorAll('[class*="overflow-wrap"]');
      expect(names.length, `${room.id}/${task.id}`).toBe(flattenRaw(raw).length);
      unmount();
    }
  }, 120_000);
});

describe("raw log rows", () => {
  it("no room component sets a fixed, unwrapped field-name column", () => {
    const files: string[] = [];
    const walk = (d: string) => { for (const f of readdirSync(d)) { const p = join(d, f); if (statSync(p).isDirectory()) walk(p); else if (p.endsWith(".tsx") && !p.includes(".test.")) files.push(p); } };
    walk(join(process.cwd(), "src", "components", "operation"));
    walk(join(process.cwd(), "src", "components", "rooms"));
    const bad = files.filter(f => /\{(f\.key|k)\}<\/span>/.test(readFileSync(f, "utf8")) && /className="[^"]*(w-\d+ shrink-0|shrink-0 min-w-)[^"]*">\{(f\.key|k)\}/.test(readFileSync(f, "utf8")));
    expect(bad).toEqual([]);
  });
});
