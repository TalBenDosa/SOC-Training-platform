// @vitest-environment jsdom
import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { ROLL_MS, useClearRoll } from "./useClearRoll";
import type { HubStation } from "./types";

const st = (id: string, status: HubStation["status"]) => ({ id, label: id, status, stars: 0, progress: "0/1" }) as HubStation;
const KEY = "soc:operation:rolled:room";
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

/** A hook host: the project has no testing library, and this needs only one component. */
function renderHook<P, R>(hook: (p: P) => R, options?: { initialProps: P }) {
  const result = { current: undefined as R };
  const Host = ({ p }: { p: P }) => { result.current = hook(p); return null; };
  const root = createRoot(document.createElement("div"));
  const rerender = (p: P) => act(() => { root.render(React.createElement(Host, { p })); });
  rerender(options?.initialProps as P);
  return { result, rerender };
}

describe("useClearRoll", () => {
  beforeEach(() => { localStorage.clear(); vi.useFakeTimers(); });
  afterEach(() => vi.useRealTimers());

  it("does not replay what a learner cleared before the feature existed", () => {
    const { result } = renderHook(() => useClearRoll("room", [st("a", "cleared"), st("b", "open")], true, false));
    act(() => { vi.advanceTimersByTime(1000); });
    expect(result.current.rolling).toBeNull();
    expect(result.current.unrolled).toEqual([]);
    expect(JSON.parse(localStorage.getItem(KEY)!)).toEqual(["a"]);
  });

  it("waits for the main screen, rolls once, then remembers", () => {
    const { result, rerender } = renderHook(({ s, on }) => useClearRoll("room", s, on, false), { initialProps: { s: [st("a", "open"), st("b", "locked")], on: true } });
    // Cleared inside the station: nothing plays yet, and the card keeps its front face
    rerender({ s: [st("a", "cleared"), st("b", "open")], on: false });
    act(() => { vi.advanceTimersByTime(2000); });
    expect(result.current.rolling).toBeNull();
    expect(result.current.unrolled).toEqual(["a"]);
    rerender({ s: [st("a", "cleared"), st("b", "open")], on: true });
    act(() => { vi.advanceTimersByTime(800); });
    expect(result.current.rolling).toBe(0);
    act(() => { vi.advanceTimersByTime(ROLL_MS); });
    expect(result.current.rolling).toBeNull();
    expect(result.current.unrolled).toEqual([]);
    expect(JSON.parse(localStorage.getItem(KEY)!)).toEqual(["a"]);
    act(() => { vi.advanceTimersByTime(5000); });
    expect(result.current.rolling).toBeNull();
  });

  it("skips the motion for a learner who asked for less of it", () => {
    localStorage.setItem(KEY, "[]");
    const { result } = renderHook(() => useClearRoll("room", [st("a", "cleared")], true, true));
    expect(result.current.rolling).toBeNull();
    expect(result.current.unrolled).toEqual([]);
    expect(JSON.parse(localStorage.getItem(KEY)!)).toEqual(["a"]);
  });
});
