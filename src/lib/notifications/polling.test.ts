import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { shouldPoll, startNotificationPolling } from "./polling";

describe("startNotificationPolling", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it("focus + visibilitychange together trigger ONE refresh (debounced)", () => {
    const refresh = vi.fn();
    const stop = startNotificationPolling(refresh, { pollMs: 60_000, debounceMs: 400 });
    window.dispatchEvent(new Event("focus"));
    document.dispatchEvent(new Event("visibilitychange"));
    window.dispatchEvent(new Event("focus"));
    expect(refresh).not.toHaveBeenCalled();
    vi.advanceTimersByTime(400);
    expect(refresh).toHaveBeenCalledTimes(1);
    stop();
  });

  it("polls on the interval while visible", () => {
    const refresh = vi.fn();
    const stop = startNotificationPolling(refresh, { pollMs: 1_000, debounceMs: 400 });
    vi.advanceTimersByTime(3_000);
    expect(refresh).toHaveBeenCalledTimes(3);
    stop();
  });

  it("does not refresh while the tab is hidden", () => {
    const spy = vi.spyOn(document, "visibilityState", "get").mockReturnValue("hidden");
    const refresh = vi.fn();
    const stop = startNotificationPolling(refresh, { pollMs: 1_000, debounceMs: 10 });
    vi.advanceTimersByTime(5_000);
    document.dispatchEvent(new Event("visibilitychange"));
    vi.advanceTimersByTime(10);
    expect(refresh).not.toHaveBeenCalled();
    stop();
    spy.mockRestore();
  });

  it("stop() removes the interval and the listeners", () => {
    const refresh = vi.fn();
    const stop = startNotificationPolling(refresh, { pollMs: 1_000, debounceMs: 10 });
    stop();
    vi.advanceTimersByTime(5_000);
    window.dispatchEvent(new Event("focus"));
    vi.advanceTimersByTime(10);
    expect(refresh).not.toHaveBeenCalled();
  });
});

describe("shouldPoll", () => {
  it("never for guests or a user the server switched off", () => {
    expect(shouldPoll(null, null)).toBe(false);
    expect(shouldPoll("u1", "u1")).toBe(false);
    expect(shouldPoll("u1", null)).toBe(true);
    expect(shouldPoll("u2", "u1")).toBe(true);   // a different user signs in → poll again
  });
});
