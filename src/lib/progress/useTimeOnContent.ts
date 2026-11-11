"use client";
/**
 * Measures ACTIVE time on a lesson or a quiz and reports it to POST /api/progress/time
 * (migration 0109), so an org admin can compare it with a learning plan's target time.
 *
 * A second counts only while the tab is visible and the learner did something (scroll, key,
 * pointer, touch) in the last two minutes: a tab left open overnight adds nothing. Beats go
 * out every 60 seconds and once more when the page is hidden or left (sendBeacon, so it
 * survives navigation). Guests and failures are silent by design.
 */
import { useEffect } from "react";

const IDLE_MS = 2 * 60_000;
const BEAT_MS = 60_000;

export function useTimeOnContent(kind: "lesson" | "quiz", id: string | null | undefined): void {
  useEffect(() => {
    if (!id || typeof window === "undefined") return;
    let lastActive = Date.now();
    let pending = 0;
    const mark = () => { lastActive = Date.now(); };
    const tick = window.setInterval(() => {
      if (document.visibilityState === "visible" && Date.now() - lastActive < IDLE_MS) pending++;
    }, 1000);
    const send = (useBeacon: boolean) => {
      if (pending < 5) return;
      const body = JSON.stringify({ kind, id, seconds: Math.min(pending, 120) });
      pending = 0;
      try {
        if (useBeacon && navigator.sendBeacon) navigator.sendBeacon("/api/progress/time", new Blob([body], { type: "application/json" }));
        else void fetch("/api/progress/time", { method: "POST", headers: { "Content-Type": "application/json" }, body, keepalive: true }).catch(() => {});
      } catch { /* best effort */ }
    };
    const beat = window.setInterval(() => send(false), BEAT_MS);
    const onHide = () => { if (document.visibilityState === "hidden") send(true); };
    const onLeave = () => send(true);
    const events = ["pointerdown", "keydown", "scroll", "wheel", "touchstart"] as const;
    for (const e of events) window.addEventListener(e, mark, { passive: true });
    document.addEventListener("visibilitychange", onHide);
    window.addEventListener("pagehide", onLeave);
    return () => {
      send(true);
      window.clearInterval(tick);
      window.clearInterval(beat);
      for (const e of events) window.removeEventListener(e, mark);
      document.removeEventListener("visibilitychange", onHide);
      window.removeEventListener("pagehide", onLeave);
    };
  }, [kind, id]);
}
