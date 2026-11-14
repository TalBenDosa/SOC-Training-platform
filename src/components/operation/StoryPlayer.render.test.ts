// A room film that stalls (the frame freezes with no error and no "ended" event) must not trap the
// learner: a watchdog continues the mission, and real progress cancels it (feedback 2026-11-14).
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { StoryPlayer } from "./StoryPlayer";

const clip = { title: "Chapter 1", src: "https://example.test/film.mp4", poster: "https://example.test/p.jpg" } as never;

let container: HTMLDivElement;
let root: Root;
// jsdom does not implement media playback: give play() a resolved promise and report the element as
// actively playing (not paused), so the stall path behaves as it would during real playback.
beforeEach(() => {
  vi.useFakeTimers();
  Object.defineProperty(HTMLMediaElement.prototype, "play", { configurable: true, value: vi.fn().mockResolvedValue(undefined) });
  Object.defineProperty(HTMLMediaElement.prototype, "paused", { configurable: true, get: () => false });
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.useRealTimers();
});

function fire(type: string) {
  const v = container.querySelector("video")!;
  act(() => { v.dispatchEvent(new Event(type)); });
}

describe("StoryPlayer stall handling", () => {
  it("continues the mission when the film stalls and never recovers", () => {
    const onDone = vi.fn();
    act(() => { root.render(React.createElement(StoryPlayer, { clip, label: "Briefing", onDone })); });
    fire("waiting");                    // the film froze mid-play
    expect(container.textContent).toContain("Loading");   // spinner shows, so it reads as loading not broken
    act(() => { vi.advanceTimersByTime(15_000); });       // STALL_CONTINUE_MS
    expect(onDone).toHaveBeenCalledTimes(1);
  });

  it("does NOT continue when the film recovers and keeps playing", () => {
    const onDone = vi.fn();
    act(() => { root.render(React.createElement(StoryPlayer, { clip, label: "Briefing", onDone })); });
    fire("waiting");
    fire("timeupdate");                 // frames flowing again: watchdog must be disarmed
    act(() => { vi.advanceTimersByTime(30_000); });
    expect(onDone).not.toHaveBeenCalled();
  });

  it("continues immediately when the film ends", () => {
    const onDone = vi.fn();
    act(() => { root.render(React.createElement(StoryPlayer, { clip, label: "Briefing", onDone })); });
    fire("ended");
    expect(onDone).toHaveBeenCalledTimes(1);
  });
});
