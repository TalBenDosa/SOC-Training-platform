// QA phase 7, E-01: a room task whose grading request fails tells the learner why
// (it used to fail silently), and a flag task is never left stuck on "checking".
import { describe, it, expect, vi, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
vi.mock("./MermaidDiagram", () => ({ MermaidDiagram: () => null }));
import { TaskPlayer } from "./TaskPlayer";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
const question = { type: "question", id: "q1", question: "Which port does RDP use?", options: ["22", "3389", "443"], answer: 1, explanation: "", xp: 20 };
const flag = { type: "flag", id: "f1", prompt: "Enter the attacker IP", answer: "1.2.3.4", xp: 30, event: null };

describe("TaskPlayer — failed grading", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); vi.unstubAllGlobals(); });
  const mount = (task: unknown) => {
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    act(() => { root!.render(React.createElement(TaskPlayer, { roomId: "r1", task: task as never, onComplete: () => {}, isCompleted: false })); });
  };
  const button = (re: RegExp) => [...el!.querySelectorAll("button")].find(b => re.test(b.textContent ?? ""))!;

  it("a 503 from the grader shows the server's message", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: "Couldn't save your answer — please try again." }), { status: 503 })));
    mount(question);
    await act(async () => { button(/3389/).click(); });
    await act(async () => { button(/confirm|submit|check/i).click(); });
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
    expect(el!.querySelector('[role="alert"]')?.textContent).toContain("Couldn't save your answer — please try again.");
  });

  it("an expired session says so (not \"check your connection\")", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: "Authentication required." }), { status: 401 })));
    mount(question);
    await act(async () => { button(/3389/).click(); });
    await act(async () => { button(/confirm|submit|check/i).click(); });
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
    expect(el!.querySelector('[role="alert"]')?.textContent).toMatch(/session expired/i);
  });

  it("a flag task is not left on \"checking\" after a network failure", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("Failed to fetch"); }));
    mount(flag);
    const input = el!.querySelector("input") as HTMLInputElement;
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
      setter.call(input, "1.2.3.4"); input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const submit = [...el!.querySelectorAll("button")].find(b => /submit|check/i.test(b.textContent ?? "") && !b.disabled)!;
    await act(async () => { submit.click(); });
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
    expect(el!.querySelector('[role="alert"]')?.textContent).toMatch(/couldn't reach the server/i);
    const again = [...el!.querySelectorAll("button")].find(b => /submit|check/i.test(b.textContent ?? ""))!;
    expect(again.disabled).toBe(false);
  });
});
