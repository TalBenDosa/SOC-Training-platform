// The field-read lab (SPEC-field-labs.md): answers come from the artifact, a wrong line says what that
// line really is, and the lab reports done once, after the last objective.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { ReaderLab } from "./ReaderLab";
import { WEB_ATTACKS_PRACTICE } from "@/lib/rooms/experience/webAttacksPractice";
import type { BriefingLab } from "@/lib/rooms/experience";

type Reader = Extract<BriefingLab, { kind: "reader" }>;
const lab = WEB_ATTACKS_PRACTICE.briefings!["web-r1"][0] as Reader;

let container: HTMLDivElement;
let root: Root;
beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

const lineButtons = () => [...container.querySelectorAll<HTMLButtonElement>("button[aria-pressed]")];
const clickText = (text: string) => {
  const b = [...container.querySelectorAll("button")].find(x => x.textContent?.trim() === text);
  if (!b) throw new Error(`no button "${text}"`);
  act(() => { b.click(); });
};
function type(value: string) {
  const input = container.querySelector<HTMLInputElement>("input[aria-label^='Answer']")!;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  act(() => { setter.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); });
}
function answer(o: Reader["objectives"][number]) {
  if (o.type === "line") { act(() => { lineButtons()[o.answer[0]].click(); }); }
  else type(o.type === "count" ? String(o.answer) : o.answer[0]);
  clickText("Check");
}

describe("ReaderLab", () => {
  it("renders every line of the artifact and its header", () => {
    act(() => root.render(React.createElement(ReaderLab, { lab, onDone: () => {} })));
    expect(lineButtons().length).toBe(lab.lines.length);
    expect(container.textContent).toContain("#Fields: date time s-ip");
  });

  it("a wrong line explains what that line is, and does not advance", () => {
    act(() => root.render(React.createElement(ReaderLab, { lab, onDone: () => {} })));
    act(() => { lineButtons()[9].click(); });
    clickText("Check");
    expect(container.textContent).toContain(lab.notes![9]);
    expect(container.textContent).not.toContain(lab.objectives[0].why);
  });

  it("a value that is not in the log is told so", () => {
    act(() => root.render(React.createElement(ReaderLab, { lab, onDone: () => {} })));
    answer(lab.objectives[0]);
    type("77777");
    clickText("Check");
    expect(container.textContent).toContain("does not appear in the log");
  });

  it("filtering narrows the lines and keeps their original numbers", () => {
    act(() => root.render(React.createElement(ReaderLab, { lab, onDone: () => {} })));
    const filter = container.querySelector<HTMLInputElement>("input[aria-label='Filter the log lines']")!;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
    act(() => { setter.call(filter, "WAITFOR"); filter.dispatchEvent(new Event("input", { bubbles: true })); });
    const shown = lineButtons();
    expect(shown.length).toBe(2);
    expect(shown[0].textContent?.startsWith("14")).toBe(true);
  });

  it("answering every objective from the log finishes the lab once", () => {
    const onDone = vi.fn();
    act(() => root.render(React.createElement(ReaderLab, { lab, onDone })));
    for (const o of lab.objectives) answer(o);
    expect(onDone).toHaveBeenCalledTimes(1);
    expect(container.textContent).toContain(lab.lesson);
    for (const o of lab.objectives) expect(container.textContent).toContain(o.why);
  });
});
