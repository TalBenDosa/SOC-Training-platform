"use client";
import { useEffect, useRef, useState } from "react";

/**
 * Screen-reader announcements for items that stream into a live panel
 * (WCAG 4.1.3 Status Messages). Announces NEW items only — never the history
 * present when the panel mounts (or that arrives in its first moments, e.g. the
 * initial event load) — and throttles, so a burst of items becomes ONE concise
 * summary instead of a flood.
 *
 * Render the returned text in <LiveRegion> (a visually hidden role="status").
 */
export function useNewItemsAnnouncement<T>(
  items: readonly T[],
  keyOf: (item: T) => string | number,
  describe: (fresh: T[]) => string,
  { throttleMs = 8000, settleMs = 2000 }: { throttleMs?: number; settleMs?: number } = {},
): string {
  const [message, setMessage] = useState("");
  const seen = useRef<Set<string | number> | null>(null);
  const pending = useRef<T[]>([]);
  const lastAt = useRef(0);
  const mountedAt = useRef(0);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const describeRef = useRef(describe);
  describeRef.current = describe;

  useEffect(() => {
    const now = Date.now();
    if (seen.current === null) {
      // First render: everything already here is history.
      seen.current = new Set(items.map(keyOf));
      mountedAt.current = now;
      return;
    }
    const fresh = items.filter(i => !seen.current!.has(keyOf(i)));
    if (fresh.length === 0) return;
    for (const i of fresh) seen.current.add(keyOf(i));
    // The initial load can land just after mount — treat it as history too.
    if (now - mountedAt.current < settleMs) return;
    pending.current.push(...fresh);
    const flush = () => {
      timer.current = null;
      if (pending.current.length === 0) return;
      const text = describeRef.current(pending.current);
      pending.current = [];
      lastAt.current = Date.now();
      setMessage(text);
    };
    const wait = throttleMs - (now - lastAt.current);
    if (wait <= 0) flush();
    else if (!timer.current) timer.current = setTimeout(flush, wait);
    // keyOf is expected to be stable in behaviour; items drive the effect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items]);

  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);
  return message;
}

/** Visually hidden polite status region for useNewItemsAnnouncement's text. */
export function LiveRegion({ message }: { message: string }) {
  return <p className="sr-only" role="status" aria-live="polite" aria-atomic="true">{message}</p>;
}

/** Trim announcement text so a long payload doesn't monopolise the screen reader. */
export function clip(s: string, n = 140): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}
