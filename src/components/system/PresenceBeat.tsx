"use client";
/**
 * Tells the server the learner is on the platform (POST /api/progress/presence, migration 0123),
 * so an org admin's "last seen", visits and active time are true even for a learner who never
 * signs out. The last sign-in alone cannot say that: it only moves when a password is typed.
 *
 * One beat when the app opens, then one a minute while the tab is visible and the learner did
 * something (pointer, key, scroll, touch) in the last two minutes, and one when the page is hidden
 * or left (sendBeacon, so it survives navigation). A tab left open overnight adds nothing. Guests
 * are ignored by the route; failures are silent by design. Renders nothing.
 */
import { useEffect } from "react";

const IDLE_MS = 2 * 60_000;
const BEAT_MS = 60_000;
const URL = "/api/progress/presence";

export function PresenceBeat(): null {
  useEffect(() => {
    if (typeof window === "undefined") return;
    let lastActive = Date.now();
    let pending = 0;
    const mark = () => { lastActive = Date.now(); };
    const post = (seconds: number, useBeacon: boolean) => {
      const body = JSON.stringify({ seconds });
      try {
        if (useBeacon && navigator.sendBeacon) navigator.sendBeacon(URL, new Blob([body], { type: "application/json" }));
        else void fetch(URL, { method: "POST", headers: { "Content-Type": "application/json" }, body, keepalive: true }).catch(() => {});
      } catch { /* best effort */ }
    };
    const flush = (useBeacon: boolean) => {
      if (pending < 5) return;
      const seconds = Math.min(pending, 120);
      pending = 0;
      post(seconds, useBeacon);
    };
    post(0, false);   // the app was opened: seen now
    const tick = window.setInterval(() => {
      if (document.visibilityState === "visible" && Date.now() - lastActive < IDLE_MS) pending++;
    }, 1000);
    const beat = window.setInterval(() => flush(false), BEAT_MS);
    const onHide = () => { if (document.visibilityState === "hidden") flush(true); };
    const onLeave = () => flush(true);
    const events = ["pointerdown", "keydown", "scroll", "wheel", "touchstart"] as const;
    for (const e of events) window.addEventListener(e, mark, { passive: true });
    document.addEventListener("visibilitychange", onHide);
    window.addEventListener("pagehide", onLeave);
    return () => {
      flush(true);
      window.clearInterval(tick);
      window.clearInterval(beat);
      for (const e of events) window.removeEventListener(e, mark);
      document.removeEventListener("visibilitychange", onHide);
      window.removeEventListener("pagehide", onLeave);
    };
  }, []);
  return null;
}
