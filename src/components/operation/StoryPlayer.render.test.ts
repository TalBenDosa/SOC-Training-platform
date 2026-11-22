// Room story films (feedback 2026-11-14 and 2026-11-21): a stalled film must never trap the learner,
// but must not skip itself either, so a slow line does not lose the story; the learner can pause and
// seek; the 3D world behind stops rendering while a film is open; playback events are reported.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";

const sent: { kind: string; waitMs?: number; roomId?: string; clipKey?: string }[] = [];
vi.mock("@/lib/media/filmTelemetry", () => ({ sendFilmEvent: (e: { kind: string }) => { sent.push(e); } }));

const { StoryPlayer, SLOW_STALL_MS, formatClock } = await import("./StoryPlayer");
const { worldsPaused } = await import("./worldPause");

const clip = { title: "Chapter 1", src: "https://example.test/film.mp4", poster: "https://example.test/p.jpg" } as never;

let container: HTMLDivElement;
let root: Root;
let paused = false;
// jsdom does not implement media playback: play() resolves and flips paused; pause() flips it back.
beforeEach(() => {
  vi.useFakeTimers();
  sent.length = 0;
  paused = false;
  Object.defineProperty(HTMLMediaElement.prototype, "play", { configurable: true, value: vi.fn(function (this: HTMLMediaElement) { paused = false; return Promise.resolve(); }) });
  Object.defineProperty(HTMLMediaElement.prototype, "pause", { configurable: true, value: vi.fn(function (this: HTMLMediaElement) { paused = true; this.dispatchEvent(new Event("pause")); }) });
  Object.defineProperty(HTMLMediaElement.prototype, "load", { configurable: true, value: vi.fn() });
  Object.defineProperty(HTMLMediaElement.prototype, "paused", { configurable: true, get: () => paused });
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
const button = (name: string) => [...container.querySelectorAll("button")].find(b => (b.getAttribute("aria-label") ?? b.textContent ?? "").includes(name));
const render = (onDone = vi.fn()) => { act(() => { root.render(React.createElement(StoryPlayer, { clip, label: "Briefing", onDone, roomId: "malware-analysis-fundamentals", clipKey: "intro" })); }); return onDone; };

describe("StoryPlayer stall handling", () => {
  it("a long stall offers Try again / Continue, and never skips on its own", () => {
    const onDone = render();
    fire("waiting");                                       // the film froze mid-play
    expect(container.textContent).toContain("Loading");
    act(() => { vi.advanceTimersByTime(SLOW_STALL_MS); });
    expect(container.textContent).toContain("loading slowly");
    act(() => { vi.advanceTimersByTime(120_000); });
    expect(onDone).not.toHaveBeenCalled();
    act(() => { button("Continue the mission")!.click(); });
    expect(onDone).toHaveBeenCalledTimes(1);
    expect(sent.map(e => e.kind)).toEqual(["stall", "continue"]);
  });

  it("Try again reloads the film; progress afterwards clears the choice and reports the wait", () => {
    const onDone = render();
    fire("waiting");
    act(() => { vi.advanceTimersByTime(SLOW_STALL_MS); });
    act(() => { button("Try again")!.click(); });
    expect(HTMLMediaElement.prototype.load).toHaveBeenCalled();
    fire("timeupdate");
    expect(container.textContent).not.toContain("loading slowly");
    const recovered = sent.find(e => e.kind === "recovered")!;
    expect(recovered.waitMs).toBeGreaterThanOrEqual(SLOW_STALL_MS);
    expect(onDone).not.toHaveBeenCalled();
  });

  it("a short stall that recovers shows nothing more", () => {
    const onDone = render();
    fire("waiting");
    fire("timeupdate");
    act(() => { vi.advanceTimersByTime(30_000); });
    expect(container.textContent).not.toContain("loading slowly");
    expect(onDone).not.toHaveBeenCalled();
  });

  it("a film the learner paused is not a stall", () => {
    render();
    fire("playing");
    act(() => { button("Pause")!.click(); });
    fire("waiting");
    act(() => { vi.advanceTimersByTime(SLOW_STALL_MS * 2); });
    expect(container.textContent).not.toContain("loading slowly");
    expect(sent.some(e => e.kind === "stall")).toBe(false);
  });

  it("continues immediately when the film ends, reporting it once", () => {
    const onDone = render();
    fire("playing");
    fire("ended");
    fire("ended");
    expect(onDone).toHaveBeenCalledTimes(1);
    expect(sent.map(e => e.kind)).toEqual(["start", "ended"]);
    expect(sent[0]).toMatchObject({ roomId: "malware-analysis-fundamentals", clipKey: "intro" });
  });
});

describe("StoryPlayer controls", () => {
  it("has play/pause, back 10 seconds, a seek bar and mute", () => {
    render();
    fire("playing");
    expect(button("Pause")).toBeTruthy();
    expect(button("Back 10 seconds")).toBeTruthy();
    expect(button("Mute")).toBeTruthy();
    expect(container.querySelector('input[type="range"][aria-label="Seek"]')).toBeTruthy();
    act(() => { button("Pause")!.click(); });
    expect(button("Play")).toBeTruthy();
  });

  it("Skip reports a skip and hands control back", () => {
    const onDone = render();
    act(() => { button("Skip")!.click(); });
    expect(onDone).toHaveBeenCalledTimes(1);
    expect(sent.at(-1)!.kind).toBe("skipped");
  });

  it("formats the clock", () => {
    expect(formatClock(0)).toBe("0:00");
    expect(formatClock(51.3)).toBe("0:51");
    expect(formatClock(125)).toBe("2:05");
    expect(formatClock(NaN)).toBe("0:00");
  });
});

describe("the room world pauses behind a film", () => {
  it("holds the pause while the film is open and releases it on close", () => {
    expect(worldsPaused()).toBe(false);
    render();
    expect(worldsPaused()).toBe(true);
    act(() => root.unmount());
    expect(worldsPaused()).toBe(false);
    root = createRoot(container);                          // afterEach unmounts again
  });
});
